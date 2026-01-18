#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <regex>
using namespace std;

string toLower(string str) {
    for (char &c : str) {
        c = tolower(c);
    }
    return str;
}

struct Rule {
    string action;
    string protocol;
    string srcIP;
    int srcIPport;
    string dstIP;
    int dstIPport;
    string message;
    int sid;
    int rev;
};
vector<Rule> rules;
struct LogEntry{
    string srcIP;
    string dstIP;
    string protocol;
    int port;
    string payload;
};
vector<LogEntry> logs;

bool parseLogLine(const string &line, LogEntry &entry){
    //Parse line
    stringstream ss(line);
    //Enter values
    if (!(ss >> entry.srcIP >> entry.dstIP >> entry.protocol >> entry.port >> entry.payload)){
        cout<<"Malformed line: "<<line<<endl;
        return false; //parsing failed
    }
    
    return true;//Parsing succeeded
}
void showLogs(const vector<LogEntry>& logs){
    int counter = 1;
    for (const auto& log : logs){
        cout <<counter<<'.'<<log.srcIP<<" -> "<<log.dstIP<<" "<<log.protocol<<" "<<log.port<<" "<<log.payload<<endl;
        counter++;
    }
}
void showRules(const vector<Rule>& rules){
    int counter = 1;
    for (const auto& rule : rules){
        cout <<counter<<". ["<<rule.action<<"] "<<rule.protocol<<" "<<rule.srcIP<<" "<<rule.srcIPport<<" -> "<<rule.dstIP<<" "<<rule.dstIPport<<" \""<<rule.message<<"\" sid:"<<rule.sid<<" rev:"<<rule.rev<<endl;
        counter++;
    }
}
void checkForAlert(const vector<LogEntry>& logs, const vector<Rule>& rules){
    for (const auto& log:logs){
        for (const auto& rule:rules){
            if (toLower(log.protocol) == toLower(rule.protocol) && log.port == rule.dstIPport && log.srcIP == rule.srcIP && log.dstIP == rule.dstIP){
                cout << "[" << rule.action << "] " << rule.message 
                     << " from " << log.srcIP << " -> " << log.dstIP 
                     << " sid:" << rule.sid << endl;
            }
        }
    }
}

int main(){
    // Read file
    ifstream tFile("traffic.log");
    ifstream rFile("rules.txt");
    if (!tFile.is_open()){
        cout << "Failed to open Traffic file!\n";
        return 1;
    }if (!rFile.is_open()){
        cout << "Failed to open rule file!\n";
        return 1;
    }

    string tLine;
    while (getline(tFile, tLine)){ //Reading traffic file
        LogEntry entry;
        if (parseLogLine(tLine, entry)){ //only valid ones
            logs.push_back(entry);
        }
    }
    tFile.close(); //Closing traffic file
    
    const regex pattern(R"(^\s*(alert)\s(tcp|udp|icmp|ip)\s(\d+\.\d+\.\d+\.\d+)\s(\d+)\s->\s(\d+\.\d+\.\d+\.\d+)\s(\d+)\s\(msg:\"([^"]+)\";\s+sid:(\d+);\s+rev:(\d+);\))",regex::icase);
    smatch match;

    string rLine;
    while (getline(rFile, rLine)){ // Reading rules file
        Rule entry;
        if(regex_match(rLine, match, pattern)){
            entry.action = match[1];
            entry.protocol = match[2];
            entry.srcIP = match[3];
            entry.srcIPport = stoi(match[4]);
            entry.dstIP = match[5];
            entry.dstIPport = stoi(match[6]);
            entry.message = match[7];
            entry.sid = stoi(match[8]);
            entry.rev = stoi(match[9]);

            rules.push_back(entry);
        }
    }
    rFile.close(); //Closing rules file
    checkForAlert(logs, rules);
    // showRules(rules); // Show rules
    // showLogs(logs); //Show logs
    return 0;
}