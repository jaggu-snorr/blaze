#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>
#include <vector>

#include <curl/curl.h>

#include "argh.h"
#include "../vendor/rapidjson/include/rapidjson/document.h"
#include "../vendor/rapidjson/include/rapidjson/filewritestream.h"
#include "../vendor/rapidjson/include/rapidjson/writer.h"

#define DEFAULT_SIZE   5000
#define DEFAULT_SLICES 5
#define WRITE_BUF_SIZE 65536

static std::mutex mtx_out;

struct auth_options
{
    std::string type;
    std::string user;
    std::string pass;
    bool insecure;
};

struct dump_options
{
    std::string  host;
    std::string  index;
    auth_options auth;
    std::string  pit_id;
    int          slice_id;
    int          slice_max;
    int          size;
};

struct thread_state
{
    std::stringstream error;
};

struct thread_container
{
    int          slice_id;
    thread_state state;
    std::thread  thread;
};

enum class http_method
{
    GET,
    POST
};

size_t write_data(
    void   * buffer,
    size_t   size,
    size_t   nmemb,
    void   * userp)
{
    std::vector<char>* data = reinterpret_cast<std::vector<char>*>(userp);

    const char* real_buffer = reinterpret_cast<const char*>(buffer);
    size_t real_size = size * nmemb;
    data->insert(data->end(), real_buffer, real_buffer + real_size);
    return real_size;
}

bool get_or_post_data(
    CURL                * crl,
    std::string   const & url,
    auth_options  const & auth,
    std::vector<char>   * data,
    long                * response_code,
    std::string         * error,
    std::string           body = "",
    http_method           method = http_method::GET)
{
    curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(crl, CURLOPT_HTTPHEADER,    headers);
    curl_easy_setopt(crl, CURLOPT_URL,           url.c_str());
    curl_easy_setopt(crl, CURLOPT_WRITEFUNCTION, &write_data);
    curl_easy_setopt(crl, CURLOPT_WRITEDATA,     reinterpret_cast<void*>(data));

    if (auth.insecure)
    {
        curl_easy_setopt(crl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(crl, CURLOPT_SSL_VERIFYHOST, 0);
    }

    if (auth.type == "basic")
    {
        std::string user_pass = auth.user + ":" + auth.pass;
        curl_easy_setopt(crl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_easy_setopt(crl, CURLOPT_USERPWD,  user_pass.c_str());
    }

    if (!body.empty())
    {
        curl_easy_setopt(crl, CURLOPT_POSTFIELDS, body.c_str());
    }
    else if (method == http_method::POST)
    {
        curl_easy_setopt(crl, CURLOPT_POST, 1);
        curl_easy_setopt(crl, CURLOPT_POSTFIELDSIZE, 0);
    }

    CURLcode res = curl_easy_perform(crl);
    curl_slist_free_all(headers);

    if (res == CURLE_OK)
    {
        curl_easy_getinfo(crl, CURLINFO_RESPONSE_CODE, response_code);
        return true;
    }

    *error = curl_easy_strerror(res);
    return false;
}

template <typename T>
std::string json_to_string(
    T const& doc)
{
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    doc.Accept(writer);

    return buffer.GetString();
}

void write_document(
    rapidjson::Document & document,
    int                 * hits_count,
    rapidjson::Document & query)
{
    std::unique_lock<std::mutex>      lock(mtx_out);

    static char                       buffer[WRITE_BUF_SIZE];
    static rapidjson::FileWriteStream stream(stdout, buffer, sizeof(buffer));

    // Epic const unfolding.
    auto const& hits_object_value = document["hits"];
    auto const& hits_object       = hits_object_value.GetObject();
    auto const& hits_value        = hits_object["hits"];
    auto const& hits              = hits_value.GetArray();

    // Shared allocator
    auto& allocator               = document.GetAllocator();
    auto  writer                  = rapidjson::Writer<rapidjson::FileWriteStream>(stream);

    *hits_count = hits.Size();
    if (hits.Size() == 0)
    {
        return;
    }

    for (rapidjson::Value const& hit : hits)
    {
        auto meta_index      = rapidjson::Value(rapidjson::kObjectType);
        auto meta_index_id   = rapidjson::Value();
        auto meta_object     = rapidjson::Value(rapidjson::kObjectType);

        meta_index_id.SetString(hit["_id"].GetString(), allocator);

        meta_index.AddMember("_id",   meta_index_id,   allocator);

        meta_object.AddMember("index", meta_index, allocator);

        // Serialize to output stream. Do it in two steps to get
        // new-line separated JSON.

        meta_object.Accept(writer);
        stream.Put('\n');
        stream.Flush();
        writer.Reset(stream);

        hit["_source"].Accept(writer);
        stream.Put('\n');
        stream.Flush();
        writer.Reset(stream);
    }

    auto const& last_hit = hits[hits.Size() - 1];
    auto const& search_after = last_hit["sort"];

    query["search_after"].CopyFrom(search_after, query.GetAllocator());
}

void output_parser_error(
    rapidjson::Document const& doc,
    std::ostream             & stream)
{
    stream << "JSON parsing failed with code: "
           << doc.GetParseError()
           << ", at offset "
           << doc.GetErrorOffset();
}

void dump(
    dump_options const& options,
    thread_state      * state)
{
    CURL* crl = curl_easy_init();

    auto query = rapidjson::Document(rapidjson::kObjectType);
    auto& query_allocator = query.GetAllocator();

    auto slice = rapidjson::Value(rapidjson::kObjectType);
    slice.AddMember("id", rapidjson::Value(options.slice_id), query_allocator);
    slice.AddMember("max", rapidjson::Value(options.slice_max), query_allocator);

    auto pit = rapidjson::Value(rapidjson::kObjectType);
    auto pit_id = rapidjson::Value();
    pit_id.SetString(options.pit_id.c_str(), query_allocator);
    pit.AddMember("id", pit_id, query_allocator);

    // NOTE: Sort by _id is disabled in ES 8.x by default,
    //       _score is available by default in all search results.
    auto sort = rapidjson::Value(rapidjson::kArrayType);
    auto sort_options = rapidjson::Value(rapidjson::kObjectType);
    auto sort_element = rapidjson::Value(rapidjson::kObjectType);
    sort_options.AddMember("order", rapidjson::Value("asc"), query_allocator);
    sort_element.AddMember("_score", sort_options, query_allocator);
    sort.PushBack(sort_element, query_allocator);

    query.AddMember("size", rapidjson::Value(options.size), query_allocator);
    query.AddMember("slice", slice, query_allocator);
    query.AddMember("pit", pit, query_allocator);
    query.AddMember("sort", sort, query_allocator);
    query.AddMember("track_total_hits", rapidjson::Value(false), query_allocator);

    std::vector<char> buffer;
    long              response_code;
    std::string       error;

    bool res = get_or_post_data(
        crl,
        options.host + "/_search",
        options.auth,
        &buffer,
        &response_code,
        &error,
        json_to_string(query));

    if (!res)
    {
        state->error << "A HTTP error occured: " << error;
        return;
    }

    if (response_code != 200)
    {
        state->error << "Server returned HTTP status " << response_code << ": " << buffer.data();
        return;
    }

    rapidjson::Document doc;
    doc.Parse(buffer.data(), buffer.size());

    if (doc.HasParseError())
    {
        return output_parser_error(doc, state->error);
    }

    int hits_count;
    auto search_after = rapidjson::Value(rapidjson::kArrayType);
    query.AddMember("search_after", search_after, query_allocator);

    write_document(
        doc,
        &hits_count,
        query);
    
    while (hits_count > 0)
    {
        buffer.clear();

        res = get_or_post_data(
            crl,
            options.host + "/_search",
            options.auth,
            &buffer,
            &response_code,
            &error,
            json_to_string(query));

        if (!res)
        {
            state->error << "A HTTP error occured: " << error;
            return;
        }

        if (response_code != 200)
        {
            state->error << "Server returned HTTP status " << response_code;
            return;
        }

        rapidjson::Document doc_search;
        doc_search.Parse(buffer.data(), buffer.size());

        if (doc_search.HasParseError())
        {
            return output_parser_error(doc_search, state->error);
        }

        write_document(
            doc_search,
            &hits_count,
            query);
    }

    curl_easy_cleanup(crl);
}

int64_t count_documents(
    std::string  const& host,
    std::string  const& index,
    auth_options const& auth)
{
    CURL                * crl = curl_easy_init();
    long                  response_code;
    rapidjson::Document   doc;
    std::string           url = host + "/" + index + "/_count";
    std::string           error;
    std::vector<char>     buffer;

    bool res = get_or_post_data(
        crl,
        url,
        auth,
        &buffer,
        &response_code,
        &error);

    if (!res)
    {
        std::cerr << "A HTTP error occured: " << error << std::endl;
        return -1;
    }

    doc.Parse(buffer.data(), buffer.size());

    if (doc.HasParseError())
    {
        output_parser_error(doc, std::cerr);
        return -1;
    }

    return doc["count"].GetInt64();
}

std::string create_pit_id(
    std::string  const& host,
    std::string  const& index,
    auth_options const& auth)
{
    CURL                * crl = curl_easy_init();
    long                  response_code;
    rapidjson::Document   doc;
    std::string           url = host + "/" + index + "/_pit?keep_alive=1m&allow_partial_search_results=false";
    std::string           error;
    std::vector<char>     buffer;

    bool res = get_or_post_data(
        crl,
        url,
        auth,
        &buffer,
        &response_code,
        &error,
        "",
        http_method::POST);

    if (!res)
    {
        std::cerr << "A HTTP error occured: " << error << std::endl;
        return "";
    }

    doc.Parse(buffer.data(), buffer.size());

    if (doc.HasParseError())
    {
        output_parser_error(doc, std::cerr);
        return "";
    }

    return doc["id"].GetString();
}

int dump_mappings(
    std::string  const& host,
    std::string  const& index,
    auth_options const& auth)
{
    static char                       write_buffer[WRITE_BUF_SIZE];
    static rapidjson::FileWriteStream stream(stdout, write_buffer, sizeof(write_buffer));

    CURL                            * crl = curl_easy_init();
    long                              response_code;
    rapidjson::Document               doc;
    std::string                       url = host + "/" + index + "/_mapping";
    std::string                       error;
    std::vector<char>                 buffer;

    bool res = get_or_post_data(
        crl,
        url,
        auth,
        &buffer,
        &response_code,
        &error);

    if (!res)
    {
        std::cerr << "A HTTP error occured: " << error << std::endl;
        return 1;
    }

    doc.Parse(buffer.data(), buffer.size());

    if (doc.HasParseError())
    {
        output_parser_error(doc, std::cerr);
        return 1;
    }

    rapidjson::Writer<rapidjson::FileWriteStream> writer(stream);
    doc[index.c_str()].Accept(writer);
    stream.Put('\n');
    stream.Flush();

    curl_easy_cleanup(crl);

    return 0;
}

int dump_index_info(
    std::string  const& host,
    std::string  const& index,
    auth_options const& auth)
{
    static char                       write_buffer[WRITE_BUF_SIZE];
    static rapidjson::FileWriteStream stream(stdout, write_buffer, sizeof(write_buffer));

    CURL                            * crl = curl_easy_init();
    long                              response_code;
    rapidjson::Document               doc;
    std::string                       url = host + "/" + index;
    std::string                       error;
    std::vector<char>                 buffer;

    bool res = get_or_post_data(
        crl,
        url,
        auth,
        &buffer,
        &response_code,
        &error);

    if (!res)
    {
        std::cerr << "A HTTP error occured: " << error << std::endl;
        return 1;
    }

    doc.Parse(buffer.data(), buffer.size());

    if (doc.HasParseError())
    {
        output_parser_error(doc, std::cerr);
        return 1;
    }

    rapidjson::Writer<rapidjson::FileWriteStream> writer(stream);
    doc[index.c_str()].Accept(writer);
    stream.Put('\n');
    stream.Flush();

    curl_easy_cleanup(crl);

    return 0;
}

int main(
    int    argc,
    char * argv[])
{
    curl_global_init(CURL_GLOBAL_ALL);

    std::vector<std::unique_ptr<thread_container>> threads;

    // Parse command line options
    argh::parser cmdl(argv);

    std::string host;
    if (!(cmdl({"--host"}) >> host))
    {
        std::cerr << "Must provide an Elasticsearch host (--host)" << std::endl;
        return 1;
    }

    std::string index;
    if (!(cmdl({"--index"}) >> index))
    {
        std::cerr << "Must provide an index (--index)" << std::endl;
        return 1;
    }

    auth_options auth;

    if (cmdl({"--auth"}) >> auth.type)
    {
        if (auth.type == "basic")
        {
            if (!(cmdl({"--basic-username"}) >> auth.user))
            {
                std::cerr << "Must provide --basic-username when passing --auth=basic" << std::endl;
                return 1;
            }

            if (!(cmdl({"--basic-password"}) >> auth.pass))
            {
                std::cerr << "Must provide --basic-password when passing --auth=basic" << std::endl;
                return 1;
            }
        }
    }

    auth.insecure = cmdl["--insecure"];

    if (cmdl["--dump-mappings"])
    {
        return dump_mappings(
            host,
            index,
            auth);
    }
    else if (cmdl["--dump-index-info"])
    {
        return dump_index_info(
            host,
            index,
            auth);
    }

    // Sanity check - see if we have any documents in the index at all.
    if (count_documents(host, index, auth) <= 0)
    {
        std::cerr << "Index is empty - no documents found" << std::endl;
        return 0;
    }

    const auto pit_id = create_pit_id(host, index, auth);
    if (pit_id.empty())
    {
        std::cerr << "Failed to create PIT" << std::endl;
        return 1;
    }

    int slices;
    cmdl({"--slices"}, DEFAULT_SLICES) >> slices;

    int size;
    cmdl({"--size"}, DEFAULT_SIZE) >> size;

    for (int i = 0; i < slices; i++)
    {
        dump_options opts;
        opts.host      = host;
        opts.index     = index;
        opts.auth      = auth;
        opts.size      = size;
        opts.pit_id    = pit_id;
        opts.slice_id  = i;
        opts.slice_max = slices;

        auto cnt       = std::unique_ptr<thread_container>(new thread_container());
        cnt->slice_id  = i;
        cnt->thread    = std::thread(dump, opts, &cnt->state);

        threads.push_back(std::move(cnt));
    }

    int exit_code = 0;

    for (auto& cnt : threads)
    {
        cnt->thread.join();

        if (cnt->state.error.tellp() > 0)
        {
            std::cerr << "Slice "
                      << std::setw(2) << std::setfill('0') << cnt->slice_id
                      << " exited with error: "
                      << cnt->state.error.rdbuf()
                      << std::endl;

            exit_code = 1;
        }
    }

    curl_global_cleanup();

    return exit_code;
}
