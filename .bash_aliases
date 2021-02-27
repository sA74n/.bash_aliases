
# Print my public IP
alias myip='curl ipinfo.io/ip';
alias dnsvalidator_alias='dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 200 -o $tom/../my-resolvers.txt';
smule="/home/satan/Desktop/company/Smule";
indeed="/home/satan/Desktop/company/indeed";
cybrary="/home/satan/Desktop/company/cybrary";
tom="/home/satan/Desktop/tools/tom";
wordlist="/home/satan/Desktop/wordlist/";
company_path=$indeed;


#----- AWS ------- httpx -title -threads 500 -status-code -retries 5 -location -json -content-length -cname

s3ls(){
aws s3 ls s3://$1
}

s3cp(){
aws s3 cp $2 s3://$1 
}

#---- Content discovery ----
thewadl(){ #this grabs endpoints from a application.wadl and puts them in yahooapi.txt
curl -s $1 | grep path | sed -n "s/.*resource path=\"\(.*\)\".*/\1/p" | tee -a ~/tools/dirsearch/db/yahooapi.txt
}

#----- recon -----
company="/home/satan/Desktop/company";

content-discovery(){
	echo "folder-name: ";read folder_name ;
	domain_name=$1;
	mkdir $company/$folder_name;
	cd $company/$folder_name;
	#path=$company/$domain_name;

#basic details collecting
	telegram-msg "basic details collecting";
	wafw00f $domain_name > waf;
	whois $domain_name | grep -E "Registrant Organization|Registrant Email" > whois.tmp ;telegram-msg "whois result is "$(cat whois.tmp);
	rustscan $domain_name -b 1000 -- -Pn -sT -sV -sC > rustscan;
	whatweb -a 3 --log-verbose=whatweb.txt "htpps://"$domain_name;
	python3 /home/satan/Desktop/tools/dnsrecon/dnsrecon.py -f -a -s -b -y -k -w -z -v -w -d $domain_name --threads 100 -j json.txt;

#open source information gathering
	telegram-msg "open source information gathering started";
	curl "http://index.commoncrawl.org/CC-MAIN-2020-45-index?url=$domain_name*&output=json&fl=url" -o "common-crawl.txt"; cat common-crawl.txt | jq . | awk '{print $2}' | sed 's/.//;s/.$//' > urls.txt; rm common-crawl.txt;
	gau -retries 7 $domain_name|tee -a urls.txt;
	curl "http://web.archive.org/cdx/search/cdx?url=$domain_name/*&fl=original&collapse=urlkey" | tee -a urls.txt;
	

#sorting and sending them to httpx
	telegram-msg "sorting and sending them to httpx";
	cat urls.txt | sort -u | tee -a unique-urls.txt;rm urls.txt;
	cat unique-urls.txt | httpx -title -threads 200 -follow-redirects -location -status-code -content-length -retries 5 -o alive-urls.txt; rm unique-urls.txt;
	nikto -host $domain_name -port 443 -output nikto.txt;

#bruteforcing 
#start burp before bruteforcing
	echo "Shall i do Bruteforcing on "$domain_name;read brute;
	if [ $brute == "yes" ]
	then
	ffuf -r -c -t 500 -recursion -v -replay-proxy http://127.0.0.1 -w ~/Desktop/wordlist/content-discovery/raft.txt -o raft.txt -u https://$domain_name/FUZZ &
	ffuf -r -c -t 500 -recursion -v -replay-proxy http://127.0.0.1 -w ~/Desktop/wordlist/content-discovery/content-discovery.txt -o content-discovery.txt -u https://$domain_name/FUZZ &
	ffuf -r -c -t 500 -recursion -v -replay-proxy http://127.0.0.1 -w ~/Desktop/wordlist/content-discovery/directory.txt -o directory.txt -u https://$domain_name/FUZZ &
	fi

}
#start=1;end=10000;while [ $end -lt 2220000 ]; do cat all-combined.txt | sed -n "$start,$end p" > ffuf-words.txt; ffuf -r -c -rate 5 -recursion -v -replay-proxy http://127.0.0.1 -w ~/Desktop/wordlist/content-discovery/ffuf-words.txt -u https://www.glassdoor.com/FUZZ | tee -a ffuf-glassdoor.txt; start=$[$start+10000]; end=$[$end+10000]; echo $end; sleep 5m; done
# for runnning on rate limiting websites
sd-brute(){
	echo "domain name: ";read domain_name ;
	echo "company-path: "; read path;
	echo "wordlist_path1: "; read wordlist_path1;
	echo "wordlist_path2: "; read wordlist_path2;

	dnsvalidator_alias;

	aiodnsbrute_alias $domain_name $wordlist_path1 $path; telegram-msg aiodnsbrute;
	shuffledns_alias $domain_name $wordlist_path2 $path; telegram-msg shuffledns;
	telegram-msg sd-brute;
}

sd(){
	echo "Give us some details"
	echo "domain_name: "; read domain_name;
	echo "sandcastle"; read name;
	echo "cidr: "; read cidr;
	echo "asn: "; read asn;
	echo "wordlist_path1: "; read wordlist_path1;
	echo "wordlist_path2: "; read wordlist_path2;

	mkdir $company/$domain_name;
	cd $company/$domain_name;
	company_path=$company/$domain_name;

	cd $company_path;

	certspotter $domain_name | tee -a sd.txt; telegram-msg certspotter;
	crtsh $domain_name | tee -a sd.txt; telegram-msg crtsh;
	python3 /home/satan/Desktop/tools/csp-host-checker.py -d "https://"$domain_name -s $name | tee -a urls.txt;
	printf $domain_name | waybackurls | tee -a urls.txt;
	python /home/satan/Desktop/tools/sandcastle/sandcastle.py -t $name | tee -a sd.txt;
	python3 /home/satan/Desktop/tools/csp-host-checker.py -d "https://"$domain_name -s $name | tee -a sd.txt;
	gsan scan $domain_name;
	subfinder -d $domain_name -all -nW -rL $tom/../my-resolvers.txt -silent -t 200 | tee -a sd.txt; telegram-msg subfinder;
	subscraper -e 3 -t 200 --censys-api 6cad07de-31c2-43fe-aacd-eef006813779  --censys-secret 6DZjNDUfAAwzP8CrJtWxaAF6jeaRtkST -o subscraper.txt $domain_name;
	bufferover $domain_name | tee -a sd.txt; telegram-msg bufferover;
	python3 /home/satan/Desktop/tools/Sublist3r/sublist3r.py -d $domain_name -o sublister.txt; telegram-msg sublister
	if [ $cidr ] && [ $asn ]; 
	then 
	amass enum -d $domain_name -active -cidr $cidr -asn $asn -o amass-enum.txt; telegram-msg amass-enum;
 	amass intel -asn $asn -whois -rf $tom/../my-resolvers.txt -d $domain_name -o amass-intel.txt; telegram-msg amass-intel;
 	else
 	amass enum -d $domain_name -active -o amass-enum.txt; telegram-msg amass-enum.txt;
 	amass intel -whois -rf $tom/../my-resolvers.txt -d $domain_name -o amass-intel.txt; telegram-msg amass-intel;
 	fi

 	dnsvalidator_alias;

 	aiodnsbrute_alias $domain_name $wordlist_path1 $company_path; telegram-msg aiodnsbrute;
	shuffledns_alias $domain_name $wordlist_path2 $company_path; telegram-msg shuffledns;
	telegram-msg sd-brute;

	cat sd.txt aiodns.txt shuffledns.txt sublister.txt amass-enum.txt amass-intel.txt subscraper.txt| tr “[:lower:]” “[:upper:]” | sort -u | httpx -title -threads 200 -status-code -retries 5 -o httpx-subscraper.txt -cdn -follow-redirects ;
	rm sd.txt sublister.txt aiodns.txt shuffledns.txt amass-enum.txt amass-intel.txt subscraper.txt ; telegram-msg sd;

	for i in httpx-subscraper.txt; do wpscan --url $i -e vp --plugins-detection mixed --api-token t6FHlZkNOLa9qoRgm6lpEe9ICr7ETo4Y8fVD1xt1k54s > wpscan.txt; done
}


search-results(){

	echo "company_path: ";read company_path;

	echo "-----------------------------------------------------------------------";
	cd $tom/unfurl;
	search_results_file=$company_path/search-results;
	
	echo "----------------------------domains-------------------------------------------";
	cat $search_results_file | ./unfurl domains | sort -u | tee -a  $company_path/pre-domain.txt;
	echo "--------------------------------paths---------------------------------------";
	cat $search_results_file | ./unfurl paths | sort -u | tee -a  $company_path/paths.txt;
	echo "---------------------------------wordlist--------------------------------------";
	cat $company_path/paths.txt | sed 's#/#\n#g' | sort -u | tee -a $company_path/wordlist.txt;
}






#--------------------------------------------------TOOLS-------------------------------------------------------------

# dirsearch(){ #runs dirsearch and takes host and extension as arguments
#python3 ~/Desktop/tools/dirsearch/dirsearch.py -u www.glassdoor.com -F -r -w ~/Desktop/wordlist/content-discovery/all-combined.txt --debug --json-report=all.txt --matches-proxy=http://127.0.0.1
# 	python3 ~/tools/dirsearch/dirsearch.py -u $1 -E -t 50 -b 
# }
aiodnsbrute_alias(){

	aiodnsbrute $1 -f - -o json -t 1000 -r $tom/../my-resolvers.txt -w $2 > $3/aiodns.txt;	
	cat $3/aiodns.txt | jq '.[].domain' | sed 's/\"//g' | sed 's/\*\.//g' | tee -a $3/aiodnsbrute.txt; telegram-msg aiodnsbrute_alias;
}

bufferover(){
	curl http://dns.bufferover.run/dns?q="."$1 | jq '.FDNS_A[], .RDNS[]'| sed 's/\"//g' | cut -d "," -f 2 ;
}

shuffledns_alias(){
	shuffledns -d $1 -r $tom/../my-resolvers.txt -w $2 -t 500 -v -o $3/shuffledns.txt;
}


telegram-msg(){
	python3 ~/Desktop/tools/telegram-bot-cli/telegram-bot-cli.py --job "$1";
}

# ./ffuf -r -u https://www.cybrary.it/FUZZ -c -t 500 -v -w ~/Desktop/wordlist/content-discovery/raft.txt -o

webpaste(){
	echo "output path: "; read output;
	export WEBPASTE_TOKEN=iloveweb;
	cd $tom/webpaste/;
	./webpaste -p 8081 | tee -a $output;
}

# unfurl(){
# 	cd $tom/unfurl;
# 	cat $2 | unfurl $1 | sort -u ;
# }

sqlmap(){
	python ~/tools/sqlmap*/sqlmap.py -u $1 
}

burp(){
cd ~/Desktop/tools/burp
java -noverify -javaagent:burploader.jar -jar burpsuite_pro_v2020.9.2.jar
}

mscan(){ #runs masscan
sudo masscan -p 4443,2075,2076,6443,3868,3366,8443,8080,9443,9091,3000,8000,5900,8081,6000,10000,8181,3306,5000,4000,8888,5432,15672,9999,161,4044,7077,4040,9000,8089,443,744
}

certspotter(){ 
curl -s https://certspotter.com/api/v0/certs\?domain\=$1 | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u | grep $1
} #h/t Michiel Prins

crtsh(){
curl -s https://crt.sh/?Identity=%.$1 | grep ">*.$1" | sed 's/<[/]*[TB][DR]>/\n/g' | grep -vE "<|^[\*]*[\.]*$1" | sort -u | awk 'NF' | sed 's/\*\.//g'
}

open-url(){
	filename="/home/satan/Desktop/Notes/test.txt";

	while read line; 
	do
	    firefox -new-tab "$line";
	    sleep 2s;
	done < $filename
}

certnmap(){
curl https://certspotter.com/api/v0/certs\?domain\=$1 | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u | grep $1  | nmap -T5 -Pn -sS -i - -$
} #h/t Jobert Abma
#--------------------------------------------------BASH COMMANDS-------------------------------------------------------------#

#________NETWORK___________#

ncx(){
nc -l -n -vv -p $1 -k
}

ipinfo(){
curl http://ipinfo.io/$1
}


#________COMMON___________#
 count(){
cat $1 | wc -l
}

#--------------------------------------------------OTHER-------------------------------------------------------------#


crtshdirsearch(){ #gets all domains from crtsh, runs httprobe and then dir bruteforcers
curl -s https://crt.sh/?q\=%.$1\&output\=json | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | httprobe -c 50 | grep https | xargs -n1 -I{} python3 ~/tools/dirsearch/dirsearch.py -u {} -e $2 -t 50 -b 
}




