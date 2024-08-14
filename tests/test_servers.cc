#include "servers.h"
#include "string_helpers.h"

#include <charconv>
#include <climits>
#include <locale>
#include <source_location>
#include <iostream>
#include <sstream>
#include <string_view>

using dsy::string_view;
using namespace std::literals;

static uint32_t s_verbose = 0;

struct my_nump : std::numpunct<char>
{
    std::string do_grouping() const { return "\3"; }
};

std::string commas(uint64_t n)
{
    std::ostringstream s;
    s.imbue(std::locale(s.getloc(), new my_nump));
    s << n;
    return s.str();
}

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
// will have to figure out running a local dns resolver that we can add a series of generated server names to

// systemd-resolve should work as a local test dns
// conf files can be dropped in the following dirs
// /usr/lib/systemd/*.conf.d/      drwxr-xr-x
// /usr/local/lib/systemd/*.conf.d/ No such file or directory
// /etc/systemd/*.conf.d/          drwxr-xr-x

static std::vector<std::string_view> s_server_names = { "www.google.com"sv,
                                                        "www.yahoo.com"sv,
                                                        "www.microsoft.com"sv,
                                                        "en.cppreference.com"sv,
                                                        "www.facebook.com"sv,
                                                        "linux.die.net"sv };
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

void test_a4()
{
    init();
    servers my_servers;
    my_servers.add_servers(s_servers_string, 443);
    my_servers.resolve_addrs();

    if (s_verbose)
        my_servers.print_servers_detailed();

    std::string buff;
    my_servers.build_servers_string(buff, false, 5);

    const char *persist_file = "persisted_dns.txt";
    my_servers.persist_servers(persist_file, 5); // 5 sec min ttl

    servers servers_again;
    servers_again.unpersist_servers(persist_file);
    // add any new servers, then start resolution
    servers_again.add_servers(s_servers_string, 443);

    std::string buff2;
    servers_again.build_servers_string(buff2);

    if (buff != buff2)
    {
        std::cout << "buff, len: " << buff.length() << '\n' << buff << std::endl;
        std::cout << "buff2, len: " << buff2.length() << '\n' << buff2 << std::endl;
    }

    check_equals(buff, buff2, "Server strings are equal"sv);
}

int main (int argc, char **argv)
{
    for (int i = 1; i < argc; i++)
    {
        auto [key, val] = split(string_view(argv[i]), '=');
        if (key == "--server"sv)
            s_server_names.push_back(val);
        else if (key == "--verbose"sv || key == "-v"sv)
            s_verbose++;
    }
    test_a4();
}
