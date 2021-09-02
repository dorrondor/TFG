Bezero:
Bezeroak komandoa eskatzean beheko zerrendako komando bat sartu beharko zaio. 
Bezeroa exekutatzeko ./bezero exekutatu beharko da.
Konpilatzeko nahikoa da konpilatu.sh exekutatzea [./konpilatu.sh].

Main:
Bezeroak bidaltzen dion komandoaren bidez deitu beharreko funtzioari deituko dio.
Maina exekutatzeko sudo ./main exekutatu beharko da.
Konpilatzeko nahikoa da konpilatu.sh exekutatzea [./konpilatu.sh].

Daemon:
Maina bigarren gerezuan exekuzioan jartzen du.
Lehenik eta behin daemon izeneko fitxategia etc/init.d karpetan gorde beharko da. Ondoren chmod +x eginez exekuzio baimenak eman.
Daemonean start() funtzioan main exekutagarrirako path-a aldatu beharko da.
Martxan jartzeko service daemon start exekutatu beharko da terminalean. 
Ondoren terminal hori itxi ahalko da eta beste batean bezeroa exekutatuz dena martxan jarriko da.

Komandoak:
addTab <family> <table>
remTab <family> <table>
addCha <family> <table> <chain> [<hooknum> <prio> <policy>]
remCha <family> <table> <chain>
addRul <family> <table> <chain> <input/output> <proto> <port> <ip>
remRul <family> <table> <chain>
 -family: ip, ip6, inet, bridge edo arp
 -table: taularen izena (nahi dena)
 -chain: katearen izena (nahi dena)
 -hooknum: INPUT, OUTPUT, PREROUTING, POSTROUTING edo FORWARD
 -prio: zenbaki identifikatzailea, edozein zenbaki
 -policy: ACCEPT edo DROP
 -input/output: sarrera edo irteera trafikoa den, input edo output
 -proto: udp edo tcp
 -port: portu zenbakia 
 -ip: IP helbidea XXX.XXX.XXX.XXX formatuan
