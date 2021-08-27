Bezero:
Bezeroak komandoa eskatzean beheko zerrendako komando bat sartu beharko zaio. 
Bezeroa exekutatzeko ./bezero exekutatu beharko da.
Konpilatzeko nahikoa da konpilatu.sh exekutatzea [./konpilatu.sh].

Main:
Bezeroak bidaltzen dion komandoaren bidez deitu beharreko funtzioari deituko dio.
Maina exekutatzeko sudo ./main exekutatu beharko da.
Konpilatzeko nahikoa da konpilatu.sh exekutatzea [./konpilatu.sh].

Komandoak:
addTab <family> <table>
remTab <family> <table>
addCha <family> <table> <chain> [<hooknum> <prio> <policy>]
remCha <family> <table> <chain>
addRul <family> <table> <chain> [<handle>] <input/output> <proto> <port> <ip>
remRul <family> <table> <chain> [<handle>]
 -family: ip, ip6, inet, bridge edo arp
 -table: taularen izena (nahi dena)
 -chain: katearen izena (nahi dena)
 -hooknum: INPUT, OUTPUT, PREROUTING, POSTROUTING edo FORWARD
 -prio: zenbaki identifikatzailea, edozein zenbaki
 -policy: ACCEPT edo DROP
 -handle: zenbaki identifikatzailea, edozein zenbaki
 -input/output: sarrera edo irteera trafikoa den, input edo output
 -proto: udp edo tcp
 -port: portu zenbakia 
 -ip: IP helbidea XXX.XXX.XXX.XXX formatuan
