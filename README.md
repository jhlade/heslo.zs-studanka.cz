
# Webová změna hesla v Active Directory

Během koronakrize narychlo spíchnutý nástroj pro samoobslužnou změnu hesla žáků
ZŠ Pardubice - Studánka v lokálním Active Directory podle tuny podobných projektů
na GitHubu. Důvodem bylo nabídnout možnost změny hesla i při jeho vypršení, tedy
nemožnosti přihlášení se do prostředí Office 365. Zpětný zápis hesla z lokálního
AD do O365 pak provádí pravidelná synchronizace přes Azure AD Connect, proto to
může trvat až okolo 30 minut.

Základním prvkem je získání rozšířeného diagnostického LDAP kódu uživatelského
účtu z řadiče Active Directory a teprve na jeho základě je rozhodnuto o možnosti
změny hesla. Samotná změna je pak realizována pod jiným, privilegovaným účtem
(*$svcupn*). Tento účet by ideálně neměl být globálním doménovým správcem
s možností interaktivního přihlášení, měl by pouze smět spravovat objekty
v zadaných OU (v tomto případě zatím jen žáci, výhledově i nepedagogický
personál).

Vzhledem k charakteru přenášených dat musí web navenek běžet pouze pod HTTPS.

### Prerekvizity
* lokální webserver s PHP a php-ldap s přímým SSL přístupem k AD
* účet v AD s oprávněním správy objektů v zadaných OU

2020-2023 [ZŠ Pardubice - Studánka](https://www.zs-studanka.cz/)
