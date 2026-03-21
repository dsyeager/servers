#include "commas.h"
#include "log.h"
#include "servers.h"
#include "string_helpers.h"
#include "stdin_helpers.h"

#include <charconv>
#include <climits>
#include <locale>
#include <source_location>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <string_view>

using dsy::string_view;
using namespace std::literals;
using std::cout, std::cerr, std::endl;

class tester
{
public:
    tester()
    : test_cnt(0), fail_cnt(0)
    {}
    ~tester()
    {
        std::cout << "Test cnt: " << test_cnt << std::endl;
        std::cout << "Failure cnt: " << fail_cnt << std::endl;
    }

    int test_cnt;
    int fail_cnt;
};
static tester test_obj;

void check_equals(auto left, auto right, std::string_view desc, const std::source_location loc = std::source_location::current())
{
    test_obj.test_cnt++;
    if (left != right)
    {
        std::cerr << "FAILED, " << loc.function_name() << ", line: " << loc.line() << ", " << left << " != " << right << ", " << desc << std::endl;
        test_obj.fail_cnt++;
    }
}

// age old problem of maintaining a static list of servers that hopefully don't stop resolving
// I'm too network ignorant to get an elegant solution for local bind/named or resover to work with user config files
// So my initial dirty test will add entries to /etc/hosts for a list of generated server names
// That will require that the /etc/hosts file have two markers added to it for the script to determine where to insert the server names
// # SERVERS TEST HOSTS BEGIN
// # SERVERS TEST HOSTS END
// After those are in /etc/hosts run ./add_servers_to_hosts.sh <server count>
// for example "./add_servers_to_hosts.sh 10" would add 10 server names/ips to the /etc/hosts file
// Yes I know it is yuck, it requires root permissions so not safely automated in a git work flow, etc.
// If you have another solution that does not require root permissions I'm open to ideas.

static std::vector<std::string_view> s_default_server_names = { "www.google.com"sv,
                                                                "www.yahoo.com"sv,
                                                                "www.microsoft.com"sv,
                                                                "en.cppreference.com"sv,
                                                                "www.facebook.com"sv,
                                                                "linux.die.net"sv };
static std::vector<std::string_view> s_server_names;
static std::map<string_view, string_view> s_host_ip;

static std::string s_servers_string;

void init()
{
    s_servers_string = "";
    for (auto iter : s_server_names)
    {
        s_servers_string += iter;
        s_servers_string += ',';
    }
    s_servers_string.pop_back();
}

void check_host_ips(dsy::servers *srvs)
{
    if (s_host_ip.empty())
        return;
    std::string buff;

    for (auto [host, ip] : s_host_ip)
    {
        const dsy::server *srv = srvs->get_server(host);
        if (srv == nullptr)
        {
            cerr << "Not Resolved: " << host << endl;
        }
        else
        {
            buff.clear();
            srv->to_string(buff);
            if (buff.find(ip) == std::string::npos)
                cerr << "IP not found, expected " << ip << " got " << buff << endl;
        }
    }
}

void test_a4()
{
    init();
    dsy::servers my_servers;
    my_servers.add_servers(s_servers_string, 443);
    my_servers.resolve_addrs();
cerr << "my_servers resolved: " << time(0) << endl;

    if (dsy::logs::verbose)
        my_servers.print_servers_detailed();

    std::string buff;
    my_servers.build_servers_string(buff, false, 5);

    const char *persist_file = "persisted_dns.txt";
    my_servers.persist_servers(persist_file, 5); // 5 sec min ttl

    dsy::servers servers_again;
    servers_again.unpersist_servers(persist_file);
    // add any new servers, then start resolution
    servers_again.add_servers(s_servers_string, 443);
cerr << "persisted addrs tested: " << time(0) << endl;

    std::string buff2;
    servers_again.build_servers_string(buff2);

    if (buff != buff2 || dsy::logs::verbose)
    {
        cout << "buff, len: " << add_commas(buff.length()) << '\n' << buff << endl;
        cout << "buff2, len: " << add_commas(buff2.length()) << '\n' << buff2 << endl;
    }

    check_equals(buff, buff2, "Server strings are equal"sv);
cerr << "starting check of ip's: " << time(0) << endl;
    check_host_ips(&my_servers);
}

int main (int argc, char **argv)
{
    //setenv("HOSTALIASES", "./hosts", 1);
    s_server_names.reserve(10000);
    for (int i = 1; i < argc; i++)
    {
        auto [key, val] = split(string_view(argv[i]), '=');
        if (key == "--server"sv)
            s_server_names.push_back(val);
        else if (key == "--verbose"sv || key == "-v"sv)
            dsy::logs::verbose++;
    }

    std::string sbuff;

    if (s_server_names.empty() && stdin_has_data())
    {
        read_stdin(sbuff);
        // line or comma delimted data
        // each server can be "<IP> <host>" or "<host>"
        // for now the <IP> will be ignored will use it later to compare the results of resolution
        char delim = '\n';
        if (sbuff.find(delim) == std::string::npos)
            delim = ',';
        std::vector<string_view> hosts;
        string_view(sbuff).split(delim, hosts);
        for (auto hline : hosts)
        {
            auto [val1, val2] = split(hline, ' ');
            if (val2.empty())
                s_server_names.push_back(val1);
            else
            {
                s_server_names.push_back(val2);
                s_host_ip[val2] = val1;
            }
        }
    }

    if (s_server_names.empty())
    {
        s_server_names = s_default_server_names;
    }

cerr << "setup complete: " << time(0) << endl;
    test_a4();
}
