// OSI Model simulation + tests (C++17)
// Build: g++ -std=c++17 -Wall -o osi osi_model.cpp && ./osi

#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <stdexcept>
#include <sstream>
#include <iomanip>

using namespace std;

// ---------- Helpers ----------
static unsigned checksum(const string& s) {
    unsigned sum = 0;
    for (unsigned char c : s) sum = (sum + c) % 65536;
    return sum;
}

// Header format: <FIELDS>payload  (fields never contain '>')
static string wrap(const string& fields, const string& payload) {
    return "<" + fields + ">" + payload;
}
static string unwrap(const string& pdu, const string& expectedTag, string& fieldsOut) {
    if (pdu.empty() || pdu[0] != '<')
        throw runtime_error("Missing header for " + expectedTag);
    size_t end = pdu.find('>');
    if (end == string::npos) throw runtime_error("Malformed header for " + expectedTag);
    fieldsOut = pdu.substr(1, end - 1);
    if (fieldsOut.rfind(expectedTag, 0) != 0)
        throw runtime_error("Unexpected header, expected " + expectedTag);
    return pdu.substr(end + 1);
}

// ---------- Base Layer ----------
class Layer {
public:
    Layer(int number, string name) : number_(number), name_(move(name)) {}
    virtual ~Layer() = default;

    // Going DOWN the stack (sender)
    virtual string encapsulate(const string& data) = 0;
    // Going UP the stack (receiver)
    virtual string decapsulate(const string& pdu) = 0;

    int number() const { return number_; }
    const string& name() const { return name_; }

protected:
    int number_;
    string name_;
};

// ---------- Layer 7: Application ----------
class ApplicationLayer : public Layer {
public:
    ApplicationLayer() : Layer(7, "Application") {}
    string encapsulate(const string& data) override { return wrap("L7:HTTP", data); }
    string decapsulate(const string& pdu) override {
        string f; return unwrap(pdu, "L7:HTTP", f);
    }
};

// ---------- Layer 6: Presentation (encryption + encoding) ----------
class PresentationLayer : public Layer {
public:
    explicit PresentationLayer(unsigned char key = 0x5A)
        : Layer(6, "Presentation"), key_(key) {}

    string encapsulate(const string& data) override {
        ostringstream hex;
        for (unsigned char c : data)
            hex << setw(2) << setfill('0') << std::hex << int(c ^ key_);
        return wrap("L6:XOR+HEX", hex.str());
    }
    string decapsulate(const string& pdu) override {
        string f; string body = unwrap(pdu, "L6:XOR+HEX", f);
        if (body.size() % 2) throw runtime_error("L6: bad hex length");
        string out;
        for (size_t i = 0; i < body.size(); i += 2)
            out += char(stoi(body.substr(i, 2), nullptr, 16) ^ key_);
        return out;
    }
private:
    unsigned char key_;
};

// ---------- Layer 5: Session ----------
class SessionLayer : public Layer {
public:
    explicit SessionLayer(int id = 1001) : Layer(5, "Session"), id_(id) {}
    string encapsulate(const string& data) override {
        return wrap("L5:SESSION=" + to_string(id_), data);
    }
    string decapsulate(const string& pdu) override {
        string f; string body = unwrap(pdu, "L5:SESSION=", f);
        if (stoi(f.substr(11)) != id_) throw runtime_error("L5: session id mismatch");
        return body;
    }
private:
    int id_;
};

// ---------- Layer 4: Transport (ports, sequence, checksum) ----------
class TransportLayer : public Layer {
public:
    TransportLayer(int srcPort = 5000, int dstPort = 80)
        : Layer(4, "Transport"), src_(srcPort), dst_(dstPort) {}
    string encapsulate(const string& data) override {
        string f = "L4:TCP;SRC=" + to_string(src_) + ";DST=" + to_string(dst_) +
                   ";SEQ=" + to_string(seq_++) + ";CHK=" + to_string(checksum(data));
        return wrap(f, data);
    }
    string decapsulate(const string& pdu) override {
        string f; string body = unwrap(pdu, "L4:TCP", f);
        size_t p = f.find("CHK=");
        if (p == string::npos) throw runtime_error("L4: no checksum");
        unsigned chk = stoul(f.substr(p + 4));
        if (chk != checksum(body)) throw runtime_error("L4: checksum mismatch (data corrupted)");
        return body;
    }
private:
    int src_, dst_;
    int seq_ = 0;
};

// ---------- Layer 3: Network (IP addressing) ----------
class NetworkLayer : public Layer {
public:
    NetworkLayer(string src = "192.168.1.10", string dst = "10.0.0.5")
        : Layer(3, "Network"), src_(move(src)), dst_(move(dst)) {}
    string encapsulate(const string& data) override {
        return wrap("L3:IP;SRC=" + src_ + ";DST=" + dst_, data);
    }
    string decapsulate(const string& pdu) override {
        string f; string body = unwrap(pdu, "L3:IP", f);
        if (f.find("DST=" + dst_) == string::npos)
            throw runtime_error("L3: packet not addressed to this host");
        return body;
    }
private:
    string src_, dst_;
};

// ---------- Layer 2: Data Link (MAC header + FCS trailer) ----------
class DataLinkLayer : public Layer {
public:
    DataLinkLayer(string src = "AA:BB:CC:00:00:01", string dst = "AA:BB:CC:00:00:02")
        : Layer(2, "Data Link"), src_(move(src)), dst_(move(dst)) {}
    string encapsulate(const string& data) override {
        string frame = wrap("L2:ETH;SRC=" + src_ + ";DST=" + dst_, data);
        return frame + "|FCS:" + to_string(checksum(frame));
    }
    string decapsulate(const string& pdu) override {
        size_t t = pdu.rfind("|FCS:");
        if (t == string::npos) throw runtime_error("L2: missing FCS");
        string frame = pdu.substr(0, t);
        if (stoul(pdu.substr(t + 5)) != checksum(frame))
            throw runtime_error("L2: FCS error (frame corrupted)");
        string f; return unwrap(frame, "L2:ETH", f);
    }
private:
    string src_, dst_;
};

// ---------- Layer 1: Physical (bits on the wire) ----------
class PhysicalLayer : public Layer {
public:
    PhysicalLayer() : Layer(1, "Physical") {}
    string encapsulate(const string& data) override {
        string bits;
        for (unsigned char c : data)
            for (int i = 7; i >= 0; --i) bits += ((c >> i) & 1) ? '1' : '0';
        return bits;
    }
    string decapsulate(const string& bits) override {
        if (bits.size() % 8) throw runtime_error("L1: incomplete byte");
        string out;
        for (size_t i = 0; i < bits.size(); i += 8) {
            int v = 0;
            for (int j = 0; j < 8; ++j) {
                if (bits[i + j] != '0' && bits[i + j] != '1')
                    throw runtime_error("L1: invalid signal");
                v = (v << 1) | (bits[i + j] - '0');
            }
            out += char(v);
        }
        return out;
    }
};

// ---------- The full stack ----------
class OSIStack {
public:
    OSIStack() {
        layers_.push_back(make_unique<ApplicationLayer>());   // 7
        layers_.push_back(make_unique<PresentationLayer>());  // 6
        layers_.push_back(make_unique<SessionLayer>());       // 5
        layers_.push_back(make_unique<TransportLayer>());     // 4
        layers_.push_back(make_unique<NetworkLayer>());       // 3
        layers_.push_back(make_unique<DataLinkLayer>());      // 2
        layers_.push_back(make_unique<PhysicalLayer>());      // 1
    }

    // Sender: 7 -> 1
    string send(const string& msg, bool verbose = false) {
        string pdu = msg;
        for (auto& l : layers_) {
            pdu = l->encapsulate(pdu);
            if (verbose) print(*l, "encapsulate", pdu);
        }
        return pdu;
    }
    // Receiver: 1 -> 7
    string receive(const string& wire, bool verbose = false) {
        string pdu = wire;
        for (auto it = layers_.rbegin(); it != layers_.rend(); ++it) {
            pdu = (*it)->decapsulate(pdu);
            if (verbose) print(**it, "decapsulate", pdu);
        }
        return pdu;
    }
    Layer& layer(int number) {
        for (auto& l : layers_) if (l->number() == number) return *l;
        throw out_of_range("no such layer");
    }
private:
    static void print(const Layer& l, const string& op, const string& pdu) {
        string shown = pdu.size() > 70 ? pdu.substr(0, 70) + "..." : pdu;
        cout << "  [L" << l.number() << " " << l.name() << "] " << op << ": " << shown << "\n";
    }
    vector<unique_ptr<Layer>> layers_;
};

// ---------- Tests ----------
static int passed = 0, failed = 0;
#define CHECK(cond, name)                                         \
    do {                                                          \
        if (cond) { ++passed; cout << "  [PASS] " << name << "\n"; } \
        else { ++failed; cout << "  [FAIL] " << name << "\n"; }  \
    } while (0)

template <typename F>
static bool throws(F f) { try { f(); } catch (const exception&) { return true; } return false; }

static void testEachLayerRoundTrip() {
    cout << "\n== Test 1: each layer round trip ==\n";
    OSIStack s;
    for (int n = 7; n >= 1; --n) {
        Layer& l = s.layer(n);
        string in = "Hello OSI";
        CHECK(l.decapsulate(l.encapsulate(in)) == in, "Layer " + to_string(n) + " (" + l.name() + ")");
    }
}

static void testFullStack() {
    cout << "\n== Test 2: full stack send -> receive ==\n";
    OSIStack sender, receiver;
    for (string m : {"Hi", "GET /index.html", "Special chars: <>|;=\n\t!", ""}) {
        string wire = sender.send(m);
        CHECK(receiver.receive(wire) == m, "message \"" + m.substr(0, 20) + "\"");
    }
    string wire = sender.send("Hello");
    bool onlyBits = wire.find_first_not_of("01") == string::npos;
    CHECK(onlyBits, "wire contains only 0/1 bits");
}

static void testErrorDetection() {
    cout << "\n== Test 3: error detection ==\n";
    OSIStack s;
    string wire = s.send("Important data");

    string bad = wire; bad[40] = (bad[40] == '0') ? '1' : '0';  // flip one bit
    CHECK(throws([&] { s.receive(bad); }), "flipped bit is detected");

    string trunc = wire.substr(0, wire.size() - 3);
    CHECK(throws([&] { s.receive(trunc); }), "truncated signal is detected");

    CHECK(throws([&] { s.layer(1).decapsulate("01x10101"); }), "invalid signal rejected at L1");
    CHECK(throws([&] { s.layer(7).decapsulate("no header"); }), "missing header rejected at L7");
}

static void testEncryption() {
    cout << "\n== Test 4: presentation layer hides the data ==\n";
    OSIStack s;
    string enc = s.layer(6).encapsulate("secret");
    CHECK(enc.find("secret") == string::npos, "plaintext not visible after L6");
}

int main() {
    cout << "=== OSI Demo ===\n";
    OSIStack a, b;
    cout << "\nSender:\n";
    string wire = a.send("Hello from A", true);
    cout << "\nReceiver:\n";
    string msg = b.receive(wire, true);
    cout << "\nReceived message: " << msg << "\n";

    cout << "\n=== Tests ===";
    testEachLayerRoundTrip();
    testFullStack();
    testErrorDetection();
    testEncryption();

    cout << "\nResult: " << passed << " passed, " << failed << " failed\n";
    return failed == 0 ? 0 : 1;
}
