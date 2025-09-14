
// Reliable UDP-like connection over UDP socket with Flow Control
#define OPENSSL_API_COMPAT 0x10100000L
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <algorithm>
#include <vector>
#include <queue>
#include <map>
#include <string>
#include <unordered_map>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <chrono>
#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#pragma comment(lib, "ws2_32.lib")



#define FLAG_SYN 0x01
#define FLAG_ACK 0x02
#define FLAG_FIN 0x04
#define FLAG_RST 0x08

using namespace std;

int flagg = 0;


const int MAX_RECV_BUFFER = 4096;

struct Packet {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t flags;
    uint16_t payload_len;
    uint16_t window_size;

    std::vector<char> payload;

    std::vector<char> serialize() const {
        std::vector<char> buffer(17 + payload.size());
        memcpy(&buffer[0], &src_port, 2);
        memcpy(&buffer[2], &dest_port, 2);
        memcpy(&buffer[4], &seq_num, 4);
        memcpy(&buffer[8], &ack_num, 4);
        buffer[12] = flags;
        memcpy(&buffer[13], &payload_len, 2);
        memcpy(&buffer[15], &window_size, 2);
        for (int i = 0; i < (AES_BLOCK_SIZE - (payload_len % AES_BLOCK_SIZE)); i++)
        {
            buffer.push_back('i');

        }
        std::copy(payload.begin(), payload.end(), buffer.begin() + 17);
        return buffer;
    }

    static Packet deserialize(const std::vector<char>& data) {
        Packet pkt;
        memcpy(&pkt.src_port, &data[0], 2);
        memcpy(&pkt.dest_port, &data[2], 2);
        memcpy(&pkt.seq_num, &data[4], 4);
        memcpy(&pkt.ack_num, &data[8], 4);
        pkt.flags = data[12];
        memcpy(&pkt.payload_len, &data[13], 2);
        memcpy(&pkt.window_size, &data[15], 2);
        pkt.payload.assign(data.begin() + 17, data.begin() + 17 + pkt.payload_len + (AES_BLOCK_SIZE - (pkt.payload_len % AES_BLOCK_SIZE)));
        return pkt;
    }
};


class MySocket; // Forward declaration

class Connection {
public:
    Connection(MySocket* socket_, sockaddr_in addr, uint32_t initial_seq, uint32_t initial_ack)
        : socket(socket_), peer_addr(addr), seq_num(initial_seq), ack_num(initial_ack),
        established(false), N(4), fin_sent(false), fin_received(false), fully_closed(false) {
        last_activity = std::chrono::steady_clock::now();
        sender_thread = std::thread(&Connection::send_loop, this);
        timeout_thread = std::thread(&Connection::monitor_activity, this);
        //rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
        BIGNUM* bn = BN_new();
        BN_set_word(bn, RSA_F4);  // RSA_F4 = 65537
        rsa = RSA_new();
        RSA_generate_key_ex(rsa, 2048, bn, NULL);
        BN_free(bn);

    }

    ~Connection() {
        if (sender_thread.joinable()) sender_thread.join();
        if (timeout_thread.joinable()) timeout_thread.join();
        if (rsa) RSA_free(rsa);
        if (peer_rsa) RSA_free(peer_rsa);
    }

    vector<char> get_pubkey() {
        BIO* b = BIO_new(BIO_s_mem());
        PEM_write_bio_RSA_PUBKEY(b, rsa);
        size_t l = BIO_ctrl_pending(b);
        vector<char> out(l);
        BIO_read(b, out.data(), l);
        BIO_free(b);
        return out;
    }

    void init_aes_from_peer() {
        unsigned char buf[256];
        int len = RSA_private_decrypt(256, (unsigned char*)payload_buf.data(), buf, rsa, RSA_PKCS1_OAEP_PADDING);
        memcpy(aes_key, buf, 16);
        memcpy(aes_iv, buf + 16, 16);
        AES_set_encrypt_key(aes_key, 128, &aes_enc);
        AES_set_decrypt_key(aes_key, 128, &aes_dec);
        aes_ready = true;
    }

    void decrypt_payload(Packet& p) {
        if (!aes_ready) return;

        if (p.payload_len == 0)
            return;
        vector<unsigned char> out(p.payload_len + (AES_BLOCK_SIZE - (p.payload_len % AES_BLOCK_SIZE)));
        unsigned char iv_copy[AES_BLOCK_SIZE];
        memcpy(iv_copy, aes_iv, AES_BLOCK_SIZE);
        AES_cbc_encrypt((unsigned char*)p.payload.data(), out.data(), p.payload_len + (AES_BLOCK_SIZE - (p.payload_len % AES_BLOCK_SIZE)), &aes_dec, iv_copy, AES_DECRYPT);
        int pad = p.payload_len + (AES_BLOCK_SIZE - (p.payload_len % AES_BLOCK_SIZE));
        //cout << pad << "testtttt\n";

        /*for (size_t i = 0; i < 16; i++)
        {
            cout << (int)aes_iv[i] << "----------------\n";

        }*/




        p.payload.assign((char*)out.data(), (char*)out.data() + p.payload_len);

    }



    void encrypt_payload(Packet& p) {
        if (!aes_ready) return;
        int len = p.payload_len, pad = AES_BLOCK_SIZE - (len % AES_BLOCK_SIZE);
        vector<unsigned char> in(len + pad), out(len + pad);
        memcpy(in.data(), p.payload.data(), len);
        memset(in.data() + len, pad, pad);
        unsigned char iv_copy[AES_BLOCK_SIZE];
        memcpy(iv_copy, aes_iv, AES_BLOCK_SIZE);
        AES_cbc_encrypt(in.data(), out.data(), in.size(), &aes_enc, iv_copy, AES_ENCRYPT);

        p.payload.assign((char*)out.data(), (char*)out.data() + out.size());
    }

    void send(const std::string& msg);

    std::string recv(size_t expected_bytes);

    void enqueue_packet(Packet& pkt);

    void close();

    bool is_established() const { return established; }
    void set_established(bool value) { established = value; }
    void set_initial_seq(uint32_t seq) { seq_num = seq; }
    void set_initial_ack(uint32_t ack) { ack_num = ack; }
    uint32_t get_seq() const { return seq_num; }
    uint32_t get_ack() const { return ack_num; }
    sockaddr_in get_peer_addr() const { return peer_addr; }
    RSA* rsa = nullptr;
    RSA* peer_rsa = nullptr;
    unsigned char aes_key[16], aes_iv[16];
    AES_KEY aes_enc, aes_dec;
    bool aes_ready = false;


    std::vector<char> payload_buf;
private:
    void send_loop();

    void monitor_activity();

    MySocket* socket;
    sockaddr_in peer_addr;

    uint32_t seq_num;
    uint32_t ack_num;
    bool established;

    std::mutex mtx, send_mtx;
    std::condition_variable cv, send_cv;

    std::vector<char> recv_buffer;
    std::deque<Packet> send_buffer;
    std::deque<std::pair<Packet, std::chrono::steady_clock::time_point>> send_window;
    std::unordered_map<uint32_t, int> duplicate_ack_count;
    std::map<uint32_t, Packet> out_of_order_buffer;

    int N;
    const int MSS = 480;
    const int TIMEOUT_MS = 1000;
    uint16_t remote_window_size = MAX_RECV_BUFFER;
    uint16_t cwnd = 10000;

    bool fin_sent;
    bool fin_received;
    bool fully_closed;
    std::chrono::steady_clock::time_point last_activity;

    std::thread sender_thread;
    std::thread timeout_thread;
};



class MySocket {
public:
    MySocket() {
        WSAStartup(MAKEWORD(2, 2), &wsaData);
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        accepting = true;
        poll_thread = std::thread([this]() {
            while (true) {
                this->poll();
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            });
        poll_thread.detach();
    }

    ~MySocket() {
        closesocket(sockfd);
        WSACleanup();
    }

    void close() {
        accepting = false;
        cout << "---->socket closed. no more connections can add<----\n";
        if (client && default_connection->is_established()) {
            default_connection->close();
            cout << "---->client connection closed<----\n";
            //close the connection

        }
        //with this no more connections can add
    }

    bool bind(int port) {
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port);
        cout << "---->bind>----\n";
        return ::bind(sockfd, (sockaddr*)&address, sizeof(address)) == 0;
    }

    void poll() {
        sockaddr_in src;
        char buffer[1500];
        socklen_t addrlen = sizeof(src);
        int len = recvfrom(sockfd, buffer, sizeof(buffer), 0, (sockaddr*)&src, &addrlen);
        if (len <= 0) return;

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src.sin_addr, ip, INET_ADDRSTRLEN);
        int port = ntohs(src.sin_port);


        std::vector<char> data(buffer, buffer + len);
        Packet pkt = Packet::deserialize(data);
        std::string key = make_key(src);

        cout << "---->received a packet from: ip:" << ip << "  port:" << port << "  seqnum: " << pkt.seq_num << " acknum: " << pkt.ack_num << " flags: " << pkt.flags << "   <----\n";


        if ((pkt.flags & (FLAG_ACK | FLAG_SYN)) == (FLAG_ACK | FLAG_SYN)) {
            {
                std::lock_guard<std::mutex> lock(temp_pkt_mtx);
                temp_packet_queue.push({ src, pkt });
            }
            temp_cv.notify_one();
            return;
        }

        if (connections.count(key)) {
            connections[key]->enqueue_packet(pkt);
        }
        else if (temp_connections.count(key)) {
            Connection* conn = temp_connections[key];
            if (!(pkt.flags & FLAG_ACK)) {
                conn->enqueue_packet(pkt);
            }
            if (pkt.flags & FLAG_ACK) {
                conn->set_established(true);
                conn->set_initial_ack(pkt.seq_num);
                connections[key] = conn;
                pending_connections.push(conn);
                temp_connections.erase(key);
            }
        }
        else if (pkt.flags & FLAG_SYN && accepting) {
            uint32_t seq = rand() % 10000;
            uint32_t ack = pkt.seq_num + 1;
            auto* conn = new Connection(this, src, seq, ack);

            Packet syn_ack;
            syn_ack.src_port = ntohs(address.sin_port);
            syn_ack.dest_port = pkt.src_port;
            syn_ack.seq_num = conn->get_seq();
            syn_ack.ack_num = conn->get_ack();
            syn_ack.flags = FLAG_SYN | FLAG_ACK;
            //encrypt key for AES with pkt.payload and set key for aes

            BIO* bio = BIO_new_mem_buf(pkt.payload.data(), pkt.payload_len);
            PEM_read_bio_RSA_PUBKEY(bio, &conn->peer_rsa, NULL, NULL);
            BIO_free(bio);

            //create aeskey , iv
            RAND_bytes(conn->aes_key, 16);
            RAND_bytes(conn->aes_iv, 16);

            unsigned char combined[32], encrypted[256];
            memcpy(combined, conn->aes_key, 16);
            memcpy(combined + 16, conn->aes_iv, 16);
            RSA_public_encrypt(32, combined, encrypted, conn->peer_rsa, RSA_PKCS1_OAEP_PADDING);

            AES_set_encrypt_key(conn->aes_key, 128, &conn->aes_enc);
            AES_set_decrypt_key(conn->aes_key, 128, &conn->aes_dec);

            conn->aes_ready = true;
            std::vector<char> pubkey = conn->get_pubkey();

            uint16_t pubkey_len = pubkey.size();
            syn_ack.payload.clear();
            syn_ack.payload.insert(syn_ack.payload.end(), (char*)&pubkey_len, (char*)&pubkey_len + sizeof(pubkey_len));
            syn_ack.payload.insert(syn_ack.payload.end(), pubkey.begin(), pubkey.end());
            syn_ack.payload.insert(syn_ack.payload.end(), (char*)encrypted, (char*)encrypted + 256);

            syn_ack.payload_len = syn_ack.payload.size();


            send_to(syn_ack, src);

            conn->set_initial_seq(conn->get_seq() + 1);
            temp_connections[key] = conn;
        }
    }

    Connection* accept() {
        if (client)
            return nullptr;
        //we can throw a exeption
        if (pending_connections.empty()) return nullptr;
        Connection* conn = pending_connections.front();
        pending_connections.pop();

        sockaddr_in peer = conn->get_peer_addr();
        int port = ntohs(peer.sin_port);

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(peer.sin_addr), ip_str, INET_ADDRSTRLEN);

        std::cout << "----> Accepted connection from " << ip_str << ":" << port << "<----" << std::endl;


        return conn;
    }

    bool connect(const std::string& ip, int port) {
        sockaddr_in server;
        memset(&server, 0, sizeof(server));
        server.sin_family = AF_INET;
        server.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &server.sin_addr);

        uint32_t seq = rand() % 10000;
        uint32_t ack = 0;
        default_connection = new Connection(this, server, seq, ack);

        Packet syn;
        syn.src_port = 0;
        syn.dest_port = port;
        syn.seq_num = default_connection->get_seq();
        syn.ack_num = 0;
        syn.flags = FLAG_SYN;
        //how?
        std::vector<char> pubkey = default_connection->get_pubkey();
        syn.payload = pubkey;
        syn.payload_len = pubkey.size();
        send_to(syn, server);
        default_connection->set_initial_seq(default_connection->get_seq() + 1);

        while (true) {
            std::unique_lock<std::mutex> lock(temp_pkt_mtx);
            temp_cv.wait(lock, [this]() { return !temp_packet_queue.empty(); });

            auto [src, pkt] = temp_packet_queue.front();

            temp_packet_queue.pop();

            if ((pkt.flags & (FLAG_SYN | FLAG_ACK)) == (FLAG_SYN | FLAG_ACK)) {
                //decrypt with private key to get key for aes

                uint16_t pubkey_len;
                memcpy(&pubkey_len, pkt.payload.data(), 2);

                BIO* bio = BIO_new_mem_buf(pkt.payload.data() + 2, pubkey_len);
                PEM_read_bio_RSA_PUBKEY(bio, &default_connection->peer_rsa, NULL, NULL);
                BIO_free(bio);

                std::vector<char> encrypted_data(pkt.payload.begin() + 2 + pubkey_len, pkt.payload.end());
                default_connection->payload_buf = encrypted_data;


                default_connection->init_aes_from_peer();



                default_connection->set_initial_ack(pkt.seq_num + 1);

                Packet ack;
                ack.src_port = 0;
                ack.dest_port = pkt.src_port;
                ack.seq_num = default_connection->get_seq();
                ack.ack_num = default_connection->get_ack();
                ack.flags = FLAG_ACK;
                ack.payload_len = 0;
                send_to(ack, server);

                default_connection->set_established(true);
                std::string key = make_key(server);
                connections[key] = default_connection;
                //add default conn for client
                break;
            }
        }
        client = true;
        return true;
    }

    Connection* get_default_connection() { return default_connection; }

    void send_to(const Packet& pkt, const sockaddr_in& dest) {

        sockaddr_in peer = dest;
        int port = ntohs(peer.sin_port);

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(peer.sin_addr), ip_str, INET_ADDRSTRLEN);

        std::cout << "---->sending a packet from port: " << pkt.src_port << "  to dest with ip: " << ip_str << "  and port :" << pkt.dest_port << " and payloadlen:" << pkt.payload_len << "and seqnum:" << pkt.seq_num << "and acknum:" << pkt.ack_num << "  with flags:" << pkt.flags << "---->\n";



        std::vector<char> data = pkt.serialize();
        sendto(sockfd, data.data(), data.size(), 0, (sockaddr*)&dest, sizeof(dest));
    }

private:
    SOCKET sockfd;
    WSADATA wsaData;
    sockaddr_in address;

    std::mutex temp_pkt_mtx;
    std::condition_variable temp_cv;
    std::queue<std::pair<sockaddr_in, Packet>> temp_packet_queue;

    std::thread poll_thread;
    bool accepting;
    bool client;

    std::unordered_map<std::string, Connection*> connections;
    std::unordered_map<std::string, Connection*> temp_connections;
    std::queue<Connection*> pending_connections;
    Connection* default_connection = nullptr;

    std::string make_key(const sockaddr_in& addr) {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, ip, INET_ADDRSTRLEN);
        return std::string(ip) + ":" + std::to_string(ntohs(addr.sin_port));
    }
};






// Implementation of Connection methods: constructor, send, recv, close, etc.

void Connection::send(const std::string& msg) {
    std::lock_guard<std::mutex> lock(send_mtx);
    size_t offset = 0;
    while (offset < msg.size()) {
        size_t chunk = min(static_cast<size_t>(MSS), msg.size() - offset);
        Packet pkt;
        pkt.src_port = 0;
        pkt.dest_port = ntohs(peer_addr.sin_port);
        pkt.seq_num = seq_num;
        pkt.ack_num = ack_num;
        pkt.flags = 0;
        pkt.payload_len = chunk;
        pkt.payload.assign(msg.begin() + offset, msg.begin() + offset + chunk);
        encrypt_payload(pkt);
        send_buffer.emplace_back(pkt);
        offset += chunk;
        seq_num += chunk;
    }
    send_cv.notify_one();
}


std::string Connection::recv(size_t expected_bytes) {
    std::unique_lock<std::mutex> lock(mtx);
    cv.wait(lock, [this, expected_bytes] {
        return recv_buffer.size() >= expected_bytes;
        });

    std::string data(recv_buffer.begin(), recv_buffer.begin() + expected_bytes);
    recv_buffer.erase(recv_buffer.begin(), recv_buffer.begin() + expected_bytes);

    last_activity = std::chrono::steady_clock::now(); // reset timeout
    return data;
}


void Connection::enqueue_packet(Packet& pkt) {
    std::lock_guard<std::mutex> lock(mtx);
    last_activity = std::chrono::steady_clock::now();


    decrypt_payload(pkt);


    if (pkt.flags & FLAG_ACK) {
        remote_window_size = pkt.window_size;
        cwnd += MSS;
        //
        std::lock_guard<std::mutex> slock(send_mtx);
        uint32_t ack = pkt.ack_num;

        if (!send_window.empty() && ack > send_window.front().first.seq_num) {
            while (!send_window.empty() &&
                send_window.front().first.seq_num + send_window.front().first.payload_len <= ack) {
                send_window.pop_front();
            }
            duplicate_ack_count.clear();
        }
        else {
            duplicate_ack_count[ack]++;
            if (duplicate_ack_count[ack] == 3) {
                cwnd /= 2;
                //
                auto it = std::find_if(send_window.begin(), send_window.end(),
                    [ack](const auto& entry) {
                        return entry.first.seq_num == ack;
                    });
                if (it != send_window.end()) {
                    it->second = std::chrono::steady_clock::now(); // reset timer
                    socket->send_to(it->first, peer_addr); // Fast retransmit
                }
            }
        }
        send_cv.notify_one();
        return;
    }

    if (pkt.flags & FLAG_FIN) {
        fin_received = true;
        remote_window_size = pkt.window_size;
        Packet fin_ack;
        fin_ack.src_port = 0;
        fin_ack.dest_port = ntohs(peer_addr.sin_port);
        fin_ack.seq_num = seq_num;
        fin_ack.ack_num = pkt.seq_num + 1;
        fin_ack.flags = FLAG_ACK;
        fin_ack.payload_len = 0;
        socket->send_to(fin_ack, peer_addr);
        return;
    }

    // in-order
    if (pkt.seq_num == ack_num) {
        remote_window_size = pkt.window_size;
        recv_buffer.insert(recv_buffer.end(), pkt.payload.begin(), pkt.payload.end());
        ack_num += pkt.payload_len;

        // drain out-of-order buffer
        while (out_of_order_buffer.count(ack_num)) {
            Packet next_pkt = out_of_order_buffer[ack_num];
            recv_buffer.insert(recv_buffer.end(), next_pkt.payload.begin(), next_pkt.payload.end());
            ack_num += next_pkt.payload_len;
            out_of_order_buffer.erase(next_pkt.seq_num);
        }

        Packet ack;
        ack.src_port = 0;
        ack.dest_port = ntohs(peer_addr.sin_port);
        ack.seq_num = seq_num;
        ack.ack_num = ack_num;
        ack.flags = FLAG_ACK;
        ack.payload_len = 0;
        ack.window_size = MAX_RECV_BUFFER - recv_buffer.size();
        //test

        socket->send_to(ack, peer_addr);

        cv.notify_one();
    }
    else if (pkt.seq_num > ack_num) {
        remote_window_size = pkt.window_size;

        if (!out_of_order_buffer.count(pkt.seq_num)) {
            out_of_order_buffer[pkt.seq_num] = pkt;
        }

        Packet dup_ack;
        dup_ack.src_port = 0;
        dup_ack.dest_port = ntohs(peer_addr.sin_port);
        dup_ack.seq_num = seq_num;
        dup_ack.ack_num = ack_num;
        dup_ack.flags = FLAG_ACK;
        dup_ack.payload_len = 0;
        socket->send_to(dup_ack, peer_addr);
    }
}


void Connection::send_loop() {

    std::thread retransmit_thread([this]() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            std::lock_guard<std::mutex> lock(send_mtx);
            auto now = std::chrono::steady_clock::now();
            for (auto& entry : send_window) {
                if (std::chrono::duration_cast<std::chrono::milliseconds>(now - entry.second).count() > TIMEOUT_MS) {
                    entry.second = now;
                    entry.first.window_size = MAX_RECV_BUFFER - recv_buffer.size();
                    cwnd = MSS;
                    socket->send_to(entry.first, peer_addr);
                    break;
                }
            }
        }
        });
    retransmit_thread.detach();



    while (true) {
        std::unique_lock<std::mutex> lock(send_mtx);
        send_cv.wait_for(lock, std::chrono::milliseconds(100), [this] {
            return !send_buffer.empty() || !send_window.empty() || fin_sent;
            });

        if (remote_window_size == 0) {
            Packet test;
            test.src_port = 0;
            test.dest_port = ntohs(peer_addr.sin_port);
            test.seq_num = seq_num;
            test.ack_num = ack_num;
            test.flags = FLAG_ACK;
            test.payload_len = 0;
            socket->send_to(test, peer_addr);

        }

        N = min(remote_window_size, cwnd);


        if (fin_sent && send_window.empty()) break;

        size_t in_flight = 0;
        for (const auto& entry : send_window)
            in_flight += entry.first.payload_len;

        while (!send_buffer.empty() && send_window.size() < N && (in_flight + send_buffer.front().payload_len <= remote_window_size)) {
            Packet pkt = send_buffer.front();
            send_buffer.pop_front();
            pkt.window_size = MAX_RECV_BUFFER - recv_buffer.size();
            socket->send_to(pkt, peer_addr);
            send_window.emplace_back(pkt, std::chrono::steady_clock::now());
            in_flight += pkt.payload_len;
        }


    }
}


void Connection::monitor_activity() {
    while (!fully_closed) {
        std::this_thread::sleep_for(std::chrono::seconds(10));
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::minutes>(now - last_activity).count();

        if (duration >= 5) {  // 5 minutes inactivity
            std::cout << "Connection timeout due to inactivity.\n";
            close();
            break;
        }

        if (fin_sent && fin_received) {
            fully_closed = true;
        }
    }
}



void Connection::close() {
    std::lock_guard<std::mutex> lock(send_mtx);
    if (fin_sent) return;

    Packet fin;
    fin.src_port = 0;
    fin.dest_port = ntohs(peer_addr.sin_port);
    fin.seq_num = seq_num;
    fin.ack_num = ack_num;
    fin.flags = FLAG_FIN;
    fin.payload_len = 0;
    socket->send_to(fin, peer_addr);
    fin_sent = true;
    seq_num += 1;

    auto start = std::chrono::steady_clock::now();
    while (!fin_received) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        if (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start).count() > 10) {
            std::cout << "FIN-ACK not received. Force closing.\n";
            break;
        }
    }

    fully_closed = true;
    send_cv.notify_all();
}





int main() {
    MySocket server;
    if (!server.bind(12345)) {
        std::cerr << "Failed to bind server socket\n";
        return 1;
    }

    std::cout << "Server listening on port 12345...\n";

    while (true) {

        Connection* conn = server.accept();
        if (conn && conn->is_established()) {
            std::cout << "Connection established with client.\n";

            std::thread([conn]() {
                while (true) {
                    std::string msg = conn->recv(5);
                    std::cout << "Received: " << msg << "\n";
                }
                }).detach();
        }

        Sleep(10);
    }

    return 0;
}
