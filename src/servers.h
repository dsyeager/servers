#pragma once

#include "from_file.h"
#include "get_nanoseconds.h"
#include "ntoa.h"
#include "string_view.h"
#include "to_file.h"
#include "string_helpers.h"
#include "string_view.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <udns.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

using namespace std::chrono_literals;

// plan on 200K servers, probably less for a while but lets anticipate

class servers; // forward declare

class server
{
public:
    server(dsy::string_view name, uint16_t port, servers *srvs, time_t now)
    :m_name(name), m_port(port), m_servers(srvs), m_start_time(now)
    {
        dsy::string_view sv_port = name.split(' ');

        // sv_port should be ipv4 or ipv6
        // 192.168.0.4:443
        // [2001:db8:85a3:8d3:1319:8a2e:370:7348]:443
        //dsy::string_view sv_name = sv_port.rsplit(':');
        m_name = sv_port.rsplit(':');
        if (!sv_port.empty())
        {
            sv_port.aton(m_port);
        }
        m_alt_name = name;
        //std::cout << m_name << ", alt: " << m_alt_name << ", port: " << m_port << std::endl;
    }

    dsy::string_view name() const { return m_name; }
    const char* name_ptr() const { return m_name.c_str(); }

    uint16_t port() const { return m_port; }

    void add_addrinfo(addrinfo *ai) { m_addrs.push_back(std::make_pair(ai, m_addrs.size())); }
    void add_addrinfo(addrinfo *ai, uint32_t index) { m_addrs.push_back(std::make_pair(ai, index)); }

    time_t get_dns_expires() const { return m_dns_expires; }
    void set_dns_expires(uint32_t ttl) { m_dns_expires = m_start_time + ((m_end_dns - m_start_dns) / CLOCKS_PER_SEC) + ttl; }
    servers* get_servers() const { return m_servers; }

    void set_start_dns(uint64_t ns) { m_start_dns = ns; }
    void set_end_dns(uint64_t ns) { m_end_dns = ns; }
    uint64_t get_dns_ns() const { return m_end_dns - m_start_dns; }

    void print_ips() const
    {
        char s[INET6_ADDRSTRLEN];
        std::cout << m_name << " ips: " << std::endl;

        for (auto [pai, index] : m_addrs)
        {
            if (pai->ai_family == AF_INET6)
            {
        	inet_ntop(pai->ai_family,  &((struct sockaddr_in *)pai->ai_addr)->sin_addr, s, sizeof(s));
                std::cout << "\t" << s << std::endl;
            }
            else
            {
        	inet_ntop(pai->ai_family,  &((struct sockaddr_in6 *)pai->ai_addr)->sin6_addr, s, sizeof(s));
                std::cout << "\t" << s << std::endl;
            }
        }
    }

    void to_string(std::string &buff)
    {
        // <host> <expires> <csv ip list>
        buff += m_name;
        buff += ' ';
        ntoa(m_dns_expires, buff);
        char s[INET6_ADDRSTRLEN];
        for (auto [pai, index] : m_addrs)
        {
            if (pai->ai_addrlen == sizeof(struct sockaddr_in))
            {
                inet_ntop(pai->ai_family,  &((struct sockaddr_in *)pai->ai_addr)->sin_addr, s, sizeof(s));
            }
            else
            {
                inet_ntop(pai->ai_family,  &((struct sockaddr_in6 *)pai->ai_addr)->sin6_addr, s, sizeof(s));
            }
            buff << ' ' << s << ',' << index;
        }
    }

    bool from_string(dsy::string_view host, time_t expires, dsy::string_view line, addrinfo &hints)
    {
        m_dns_expires = expires;
        std::string port;
        ntoa(m_port, port);
        uint32_t ind = 0;

        while (!line.empty())
        {
            dsy::string_view index = line.split(' ');
            std::string ip(index.split(','));
            struct addrinfo* cur = nullptr;
            // use getaddrinfo to convert string IP's to addrinfo structs
            int res = getaddrinfo(ip.data(),   // node / host
                                  port.data(), // service / port
                                  &hints,    // hints
                                  &cur);
            if (res != 0)
            {
                std::cout << "getaddrinfo failed for " << ip << std::endl;
                continue;
            }
            index.aton(ind);
            add_addrinfo(cur, ind);
        }

        set_end_dns(get_nanoseconds());
        return !m_addrs.empty();
    }

    int non_blocking_connect() const
    {
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        int failures = 0;

        for (auto [pai, index] : m_addrs)
        {
// TODO handle ipv6
// delay working on connect until I have a proper ground to run my servers with.
            sockaddr *addr = pai->ai_addr;

            int res = connect(fd, (struct sockaddr*)pai->ai_addr, sizeof(*pai->ai_addr));
            if (!res || errno == EINPROGRESS)
            {
                return fd;
            }
            std::cerr << "connect failed, res: " << res
                      << ", fd: " << fd
                      << ", error: " << strerror(errno) << std::endl;
            ++failures;
        }

        return -1;
    }

    void set_a4_dns_qry(dns_query *qry) { m_a4_dns_qry = qry; }
    void set_a6_dns_qry(dns_query *qry) { m_a6_dns_qry = qry; }
    bool is_dns_pending() { return m_a4_dns_qry || m_a6_dns_qry; } // could just be return m_a4_dns_qry - m_a6_dns_qry

    size_t addr_cnt() const { return m_addrs.size(); }

private:
    std::string m_name;
    std::string m_alt_name;
    std::string m_error;
    uint16_t m_port = 0;
    addrinfo *m_dns_result = nullptr;
    std::vector<std::pair<addrinfo*, uint32_t>> m_addrs;  /**
                                                           * Each addrinfo has an ai_family attribute for AF_INET or AF_INET6
                                                           * Depending on the ai_family value cast the ai_addr to sockaddr_in or sockaddr_in6
                                                           * The uint32_t value is the index value for each address as received,
                                                           * used for sorting the addresses
                                                           */
    servers *m_servers = nullptr;
    time_t m_dns_expires = 0;
    time_t m_start_time = 0;
    uint64_t m_start_dns = 0;
    uint64_t m_end_dns = 0;
    dns_query *m_a4_dns_qry = nullptr; // public for now
    dns_query *m_a6_dns_qry = nullptr; // public for now

    // need to store the addrinfo*'s in a vector for easier sorting
    // will sort based on v4/v6 preference

    // serialize out
    // - save all the ips found in addr vector using inet_ntop
    // - <srv> <expire epoch> <ip>,<ip>,<ip>,[<ip>]
    // serialize in
    // - for each ip call getaddrinfo adding results to m_addrs.
    // - but only if not expired
};


class servers
{
public:
    servers()
    {
        dns_init(nullptr, 0); // has to be called first
        m_dns_context = dns_new(nullptr);
        dns_init(m_dns_context, 0);
        dns_open(m_dns_context);

        memset(&m_hints, 0, sizeof(addrinfo));
        m_hints.ai_family = AF_UNSPEC; // also AF_INET or AF_INET6
        m_hints.ai_socktype = SOCK_STREAM;
    }

    void add_servers(const dsy::string_view &delimited_servers, uint16_t port)
    {
        parse_delimited(delimited_servers, dsy::string_view(",\n", 2), port);
        start_resolution();
    }

    const server* get_server()
    {
/*
I'm thinking this class should be responsible for also resolving each server/host name
potentially with getaddrinfo_a, it has gai_suspend and some notifcation functionality
could:
1. read in persisted addrs
2. resolve the unresolved addrs
3. persist the resolved addrs
*/
        std::unique_lock alock(m_mutex);
std::cout << "get_server, m_run: " << m_run << std::endl;
        while (m_run && m_servers_resolved.empty() && (m_servers_processed.empty() || m_servers_processed.size() != m_servers.size()))
        {
        // might want an m_run var for early termination
       //     std::cout << "waiting, thread: " << std::this_thread::get_id() << std::endl;
            m_waiters++;
            auto ret = m_cond.wait_for(alock, 100ms);
            m_waiters--;
            if (std::cv_status::timeout == ret)
            {
                if (m_verbose)
               	    std::cout << "cond wait timed out" << std::endl;
            }
            //    std::cout << "woke up, thread: " << std::this_thread::get_id() << std::endl;
        }

        server* ret = nullptr;

        if (m_run && !m_servers_resolved.empty())
        {
            ret = m_servers_resolved.back();
            m_servers_resolved.pop_back();
            m_servers_processed.push_back(ret);
            //std::cout << "servers::get_server, moved " << ret->name() << " to the processed vector" << std::endl;
        }

        return ret;
    }

    void print_servers()
    {
        for (auto &[name, srv] : m_servers)
        {
            std::cerr << "parsed: " << name << std::endl;
        }

        for (auto &srv : m_servers_resolved)
        {
            std::cerr << "resolved: " << srv->name() << std::endl;
        }

        for (auto &srv : m_servers_processed)
        {
            std::cerr << "processed: " << srv->name() << std::endl;
        }

        std::cerr << "parsed: " << m_servers.size()
                  << ", resolved: " << m_servers_resolved.size()
                  << ", processed: " << m_servers_processed.size() << std::endl;
    }

    void build_servers_string(std::string &buff, bool verbose = false, uint32_t min_ttl = 0)
    {
        time_t min_expires = time(nullptr) + min_ttl;

        for (auto &[name, srv] : m_servers)
        {
            if (srv->get_dns_expires() < min_expires)
                continue;
            srv->to_string(buff);
            buff += '\n';
            if (verbose)
                buff << '\t' << "dns ns: " << srv->get_dns_ns() << '\n';
        }
        buff.pop_back();
    }

    void print_servers_detailed()
    {
        std::string buff;
        build_servers_string(buff, true);
        std::cout << buff << std::endl;
    }

    void persist_servers(const char* fpath, uint32_t min_ttl)
    {
        std::string buff;
        build_servers_string(buff, false, min_ttl);
        to_file(buff, fpath);
    }

    void unpersist_servers(const char* fpath)
    {
        if (!from_file(m_dns_data, fpath))
        {
            return;
        }

        dsy::string_view data(m_dns_data);

        while (!data.empty())
        {
            dsy::string_view line = data.split('\n');
            dsy::string_view host = line.split(' ');
            // no need to fully unpersist it until we actually use it
            m_dns_hosts[host] = line; // <expire time> <ip> <ip>....
        }
    }

    bool resolve_addrs()
    {
        uint32_t loops = 0;
        while (m_run && dns_active(m_dns_context))
        {
            size_t start_cnt = m_servers_resolved.size();
            time_t now = time(nullptr);
            dns_ioevent(m_dns_context, now);
            dns_timeouts(m_dns_context, 2, now);
            loops++;
            if (m_servers_resolved.size() == start_cnt)
            {
                usleep(10000);
            }
        }

        if (m_verbose)
        {
            std::cerr << "resolve_addrs, loops: " << loops
                      << ", servers resolved: " << m_servers_resolved.size() << std::endl;
        }
        return true;
    }

    uint32_t waiter_cnt() const { return m_waiters; }

    bool empty() const { return m_servers.empty(); }

    void set_max_dns_ttl(uint32_t ttl) { m_max_dns_ttl = ttl; }
    uint32_t get_max_dns_ttl() const { return m_max_dns_ttl; }

    void set_verbose(uint32_t level) { m_verbose = level; }

    void a4_resolved(struct dns_rr_a4 *result, server *srv)
    {
        srv->set_end_dns(get_nanoseconds());
        if (!result)
        {
            srv->set_a4_dns_qry(nullptr);
            if (m_verbose)
                std::cerr << "a4 failed for " << srv->name() << std::endl;
            if (!srv->is_dns_pending())
            {
                if (srv->addr_cnt())
                {
                    m_servers_resolved.push_back(srv);
                    m_cond.notify_one();
                }
                else
                    m_servers_failed_dns.push_back(srv);
            }
            return;
        }

        dsy::string_view host = result->dnsa4_cname;

        uint32_t ttl = result->dnsa4_ttl ? std::min(result->dnsa4_ttl, m_max_dns_ttl) : m_max_dns_ttl;
        if (m_verbose > 1)
            std::cerr << "a4: cname: " << result->dnsa4_cname << ", ttl: " << ttl << std::endl;

        srv->set_dns_expires(ttl);
        struct addrinfo* cur = nullptr;

        for (int i = 0; i < result->dnsa4_nrr; ++i)
        {
            sockaddr_in *addr = new struct sockaddr_in();
            addr->sin_family = AF_INET;
// in a server/daemon scenario we may be accessing multiple ports on the server
// suggesting that adding the port should come at a later stage
            addr->sin_port = htons(srv->port());
            addr->sin_addr = result->dnsa4_addr[i];
            memset(addr->sin_zero, 0, sizeof(addr->sin_zero));

            cur = construct_addrinfo(&m_hints, AF_INET);
            cur->ai_addrlen = sizeof(struct sockaddr_in);
            cur->ai_addrlen = sizeof(sockaddr_in);
            cur->ai_addr = (struct sockaddr*)addr;
            srv->add_addrinfo(cur);
        }

        std::unique_lock alock(m_mutex);
        srv->set_a4_dns_qry(nullptr);
        if (!srv->is_dns_pending())
        {
            m_servers_resolved.push_back(srv);
            m_cond.notify_one();
        }
    }

    static
    void a4_fn(dns_ctx *dns_context, struct dns_rr_a4 *result, void *data)
    {
        server *srv = static_cast<server*>(data);
        srv->get_servers()->a4_resolved(result, srv);
    }

    void a6_resolved(struct dns_rr_a6 *result, server *srv)
    {
        srv->set_end_dns(get_nanoseconds());
        if (!result)
        {
            if (m_verbose)
                std::cout << "a6 failed for " << srv->name() << std::endl;
            srv->set_a6_dns_qry(nullptr);
            if (!srv->is_dns_pending())
            {
                if (srv->addr_cnt())
                {
                    m_servers_resolved.push_back(srv);
                    m_cond.notify_one();
                }
                else
                    m_servers_failed_dns.push_back(srv);
            }
            return;
        }

        dsy::string_view host = result->dnsa6_cname;

        uint32_t ttl = result->dnsa6_ttl ? std::min(result->dnsa6_ttl, m_max_dns_ttl) : m_max_dns_ttl;
        if (m_verbose > 1)
            std::cout << "a6: cname: " << result->dnsa6_cname << ", ttl: " << ttl << std::endl;

        // assumes that v4 and v6 have same expiration
        srv->set_dns_expires(ttl);

        struct addrinfo* cur = nullptr;

        for (int i = 0; i < result->dnsa6_nrr; ++i)
        {

            sockaddr_in6 *addr = new struct sockaddr_in6();
            //addr->sin_len = sizeof(sin6);
            addr->sin6_family = AF_INET6;
            addr->sin6_flowinfo = 0;
            addr->sin6_port = htons(srv->port());
            addr->sin6_addr = result->dnsa6_addr[i];

// in a server/daemon scenario we may be accessing multiple ports on the server
// suggesting that adding the port should come at a later stage

            cur = construct_addrinfo(&m_hints, AF_INET6);
            cur->ai_addrlen = sizeof(struct sockaddr_in6);
            cur->ai_addr = (struct sockaddr*)addr;
            srv->add_addrinfo(cur);
        }

        std::unique_lock alock(m_mutex);
        srv->set_a6_dns_qry(nullptr);
        if (!srv->is_dns_pending())
        {
            m_servers_resolved.push_back(srv);
            m_cond.notify_one();
        }
    }

    static
    void a6_fn(dns_ctx *dns_context, struct dns_rr_a6 *result, void *data)
    {
        server *srv = static_cast<server*>(data);
        srv->get_servers()->a6_resolved(result, srv);
    }

private:
    addrinfo* construct_addrinfo(addrinfo *hints, int family = AF_INET)
    {
        addrinfo *cur = new struct addrinfo();
        cur->ai_next = nullptr;
        cur->ai_canonname = nullptr;
        cur->ai_socktype = hints->ai_socktype;
        cur->ai_protocol = hints->ai_protocol;
        cur->ai_flags = hints->ai_flags;
        cur->ai_family = family;

        return cur;
    }

    void parse_delimited(const dsy::string_view& buff, const dsy::string_view& delims, uint16_t port)
    {
        size_t len = buff.length();
        size_t spos = 0;
        time_t now = time(nullptr);
// TODO: rewrite this with string_view::split
        while (spos < len)
        {
            size_t epos = buff.find_first_of(delims, spos);
            dsy::string_view srv = buff.substr(spos, epos - spos);
            if (!srv.empty())
            {
                server *psrv = new server(srv, port, this, now);
                psrv->set_start_dns(get_nanoseconds());
                m_servers[psrv->name()] = psrv;
            }
            spos = epos + 1;
            if (epos == dsy::string_view::npos)
                break;
        }
    }

    void start_resolution()
    {
        time_t now = time(nullptr);
        // add unresolved srvs to m_dns_reqs
        // that suggests that we need m_servers to store a struct/class for each server
        // { srvname, addrinfo, times, bytes_sent, bytes_received, status, error }
        for (auto & [name, srv] : m_servers)
        {
            auto iter = m_dns_hosts.find(name);
            if (iter != m_dns_hosts.end())
            {
                dsy::string_view line = iter->second;
                dsy::string_view exp_str = line.split(' ');
                time_t expires = aton<time_t>(exp_str);
                if (expires > now)
                {
                    if (srv->from_string(name, expires, line, m_hints))
                    {
                        std::unique_lock alock(m_mutex);
                        m_servers_resolved.push_back(srv);
                        m_cond.notify_one();
                        continue;
                    }
                }
                else
                {
                    if (m_verbose)
                        std::cout << "start_resolution, m_dns_host entry is expired, host: " << name
                                  << ", now >= exp (" << now << " >= " << expires << "), " << exp_str << std::endl;
                }
            }

            // need to call getaddrinfo when the srv->name looks like an IP

            if (srv->is_dns_pending())
                continue;

            // TODO: think about moving the call to dns_submit_XXX into the server class
            srv->set_a4_dns_qry(dns_submit_a4(m_dns_context,
                                              srv->name_ptr(),
                                              0,
                                              a4_fn,
                                              srv));
            srv->set_a6_dns_qry(dns_submit_a6(m_dns_context,
                                              srv->name_ptr(),
                                              0,
                                              a6_fn,
                                              srv));
        }

        if (m_verbose)
            std::cout << "started resolution for " << m_servers.size() << " addrs" << std::endl;
    }

private:
    dns_ctx *m_dns_context = nullptr;
    std::unordered_map<std::string_view, server*> m_servers;

    std::string m_dns_data; // read from file
    std::unordered_map<std::string_view, std::string_view> m_dns_hosts; // points into m_dns_data

    std::vector<server*> m_servers_resolved;    // added here as they are resolved
    std::vector<server*> m_servers_processed;   // moved here when we hand them out
    std::vector<server*> m_servers_failed_dns;   // moved here when they fail to resolve
    std::mutex m_mutex;
    std::condition_variable m_cond;
    std::atomic<uint32_t> m_waiters{0};

    addrinfo m_hints;
    uint32_t m_max_dns_ttl = 6 * 3600;

    size_t m_resolved_cnt = 0;
    uint32_t m_verbose = 0;

    bool m_run = true;
};
