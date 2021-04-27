# Print my public IP
alias myip='curl ipinfo.io/ip';
alias dnsvalidator_alias='dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 200 -o $tom/../my-resolvers.txt > /dev/null';
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
	whatweb -a 3 --log-verbose=whatweb.txt "https://"$domain_name;
	python3 /home/satan/Desktop/tools/dnsrecon/dnsrecon.py -f -a -s -b -y -k -w -z -v -w -d $domain_name --threads 100 -j json.txt;

#open source information gathering
	telegram-msg "open source information gathering started";
	curl "http://index.commoncrawl.org/CC-MAIN-2020-45-index?url=$domain_name*&output=json&fl=url" -o "common-crawl.txt"; cat common-crawl.txt | jq . | awk '{print $2}' | sed 's/.//;s/.$//' > urls.txt; rm common-crawl.txt;
	gau -retries 7 $domain_name|tee -a urls.txt;
	curl "http://web.archive.org/cdx/search/cdx?url=$domain_name/*&fl=original&collapse=urlkey&output=text" | tee -a urls.txt;

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
	echo "does the folder already exists?: "; read folder_exists;
	#echo "wordlist_path1: "; read wordlist_path1;
	#echo "wordlist_path2: "; read wordlist_path2;

	if [[ $folder_exists -eq "n" ]]
	then
		mkdir $company/$domain_name;
		cd $company/$domain_name;
		company_path=$company/$domain_name;
	elif [[ $folder_exists -eq "y" ]]
	then
		echo "folder_name: "; read folder_name;
		company_path="/home/satan/Desktop/company/$folder_name";
	else
		echo "please specify"
	fi
	cd $company_path;

	echo "******certspotter started******"; certspotter $domain_name >> sd.txt;
	echo "******crt.sh started******"; crtsh $domain_name >> sd.txt;
	echo "******csp-host-checker******"; python3 /home/satan/Desktop/tools/csp-host-checker.py -d "https://"$domain_name -s $name | tee -a urls.txt;
	echo "******wayback searching started******"; curl "http://web.archive.org/cdx/search/cdx?url=*.$domain_name&fl=original&collapse=urlkey&output=text" | awk -F '/' '{print $3}' | sort -u >> sd.txt
	#python /home/satan/Desktop/tools/sandcastle/sandcastle.py -t $name | tee -a sd.txt;
	echo "******gsan started******"; gsan scan streamlabs.com | sed -n '/company-name/,$p' | sed '/company-name/d' | cut -d " " -f 2 >> sd.txt
	echo "******subfinder started******";subfinder -d $domain_name -all -nW -rL path/to/my-resolvers.txt -silent -t 200 >> sd.txt;
	echo "******subscraper started******";subscraper -e 3 -t 200 --censys-api CENSYS_API_ID  --censys-secret CENSYS_SECRET_CODE $domain_name ;cat subscraper_report.txt >> sd.txt; rm subscraper_report.txt;
	echo "******bufferover started******";bufferover $domain_name >> sd.txt;
	echo "******sublister started******";python3 /home/satan/Desktop/tools/Sublist3r/sublist3r.py -d $domain_name -o sublister.txt;cat sublister.txt >> sd.txt; rm sublister.txt
	if [ $cidr ] && [ $asn ]; 
	then 
		amass enum -d $domain_name -passive -o amass_passive;
	#amass enum -d $domain_name -active -brute -cidr $cidr -asn $asn -o amass-enum.txt; telegram-msg amass-enum;
 		amass intel -asn $asn -whois -rf $tom/../my-resolvers.txt -d $domain_name -o amass-intel.txt; telegram-msg amass-intel;
 	else
 	#amass enum -d $domain_name -active -brute -o amass-enum.txt; telegram-msg amass-enum.txt;
 		amass enum -d $domain_name -passive -o amass_passive;
 		amass intel -whois -rf $tom/../my-resolvers.txt -d $domain_name -o amass-intel.txt; telegram-msg amass-intel;
 	fi

 	cat sd.txt amass-enum.txt amass_passive amass-intel.txt subscraper_report.txt| tr “[:lower:]” “[:upper:]” | sort -u | httpx -title -threads 200 -status-code -retries 5 -o httpx-subscraper-passive.txt -cdn -follow-redirects ;
 	rm sd.txt amass-enum.txt amass-intel.txt subscraper_report.txt;

 	mkdir screenshot
 	webscreenshot -i httpx-subscraper-passive.txt -o screenshot -w 10 -v -r phantomjs --no-xserver
 	
 	dnsvalidator_alias;

 	aiodnsbrute $domain_name -f - -t 1000 -r path/to/my-resolvers.txt -w /home/satan/Desktop/wordlist/sd/httparchive_subdomains_2020_11_18.txt > aiodnsbrute.txt; cat aiodnsbrute.txt | awk '{print $2}' > aiodnsbrute;rm aiodnsbrute.txts
 	#aiodnsbrute_alias $domain_name /home/satan/Desktop/wordlist/sd/httparchive_subdomains_2020_11_18.txt $company_path; telegram-msg aiodnsbrute;
	shuffledns_alias $domain_name /home/satan/Desktop/wordlist/sd/all.txt $company_path; telegram-msg shuffledns;
	telegram-msg sd-brute;

	cat aiodnsbrute shuffledns.txt| tr “[:lower:]” “[:upper:]” | sort -u | httpx -title -threads 200 -status-code -fc 404 -retries 5 -o httpx-subscraper-brute.txt -cdn -follow-redirects ;
	#cat sd.txt aiodns.txt shuffledns.txt sublister.txt amass-enum.txt amass-intel.txt subscraper.txt| tr “[:lower:]” “[:upper:]” | sort -u |massdns -s 15000 -t A -o J -r $tom/../my-resolvers.txt --flush
	rm aiodnsbrute shuffledns.txt ; 

	for i in httpx-subscraper.txt; do wpscan --url $i -e vp --plugins-detection mixed --api-token t6FHlZkNOLa9qoRgm6lpEe9ICr7ETo4Y8fVD1xt1k54s > wpscan.txt; done
}

webscreenshot_alias(){

	echo "url_list: "; read urls_list;
	echo "output-path: "; read output-path;

	webscreenshot -i $urls_list -o $output-path -r phantomjs --no-xserver -w 2 --ajax-max-timeouts 3000,5000
}

progress(){ # a progress bar which tells us the percentage of completion of bruteforcing, when u provide output file and wordlist file

	# echo "src";read src;
	# echo "result"; read result;
	# echo "pattern"; read pattern;

	src="url-for-linkfinder";
	result="linkfinder";
	pattern="\[URL\]:"

	cat $result | tail -1000 | grep "$pattern" > 1.tmp
	got=$(cat 1.tmp | cut -d " " -f 2 | tail -1 | xargs -n1 -I@ grep -n "@" $src | cut -d ":" -f 1 | cut -d " " -f 1 );rm 1.tmp;
	
	total=$(count $src); 
	echo $(( $got*100/$total ))"%";
	
}

js-recon(){
	echo "urls list path: ";read urls_list;

	cat $urls_list | grep -iE '\.js' | grep -ivE '\.json' | sort -u >> JSfiles.txt;
	cat JSfiles.txt | httpx -title -threads 200 -status-code -retries 5 -location -follow-redirects -cdn -o liveJSfiles.txt
	cat liveJSfiles.txt | cut -d " " -f 1 | xargs -n2 -I@ bash -c "echo -e '\n[URL]: @\n'; python3 ~/Desktop/tools/LinkFinder/linkfinder.py -i @ -o cli" >> JSPathsWithURLErrors.txt;
	

	for i in {1..5}
	do
		cat JSPathsWithURLErrors.txt | grep -B2 -hr "Usage:" | grep "\[URL\]" | cut -d " " -f 2 > error-urls.txt
		cat error-urls.txt | sort -u | xargs -n2 -I@ bash -c "echo -e '\n[URL]: @\n'; python3 ~/Desktop/tools/LinkFinder/linkfinder.py -i @ -o cli" >> JSPathsWithURLErrors.txt;
	done
	cat JSPathsWithURLErrors.txt | grep -B2 -A2 -hvr "Usage:" > JSPathsWithURL.txt;
	cat JSPathsWithURL.txt | grep -iv '[URL]:' | sort -u > JSPathsWithNoURL.txt;
	cat JSPathsWithNoURL.txt | python3 ~/Desktop/tools/Bug-Bounty-Toolz/collector.py output; #to segregate folder containing urls,files,paths,params

	cat $urls_list | xargs -n2 -I@ bash -c "echo -e '\n[URL]: @\n'; python3 ~/Desktop/tools/Bug-Bounty-Toolz/getsrc.py @ " >> scriptLinks.txt;

	

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

aiodnsbrute_alias(){

	aiodnsbrute $1 -f - -o json -t 1000 -r path/to/my-resolvers.txt -w $2 > $3/aiodns.txt;	
	cat $3/aiodns.txt | jq '.[].domain' | sed 's/\"//g' | sed 's/\*\.//g' | tee -a $3/aiodnsbrute.txt; telegram-msg aiodnsbrute_alias;
}

bufferover(){
	curl http://dns.bufferover.run/dns?q="."$1 | jq '.FDNS_A[], .RDNS[]'| sed 's/\"//g' | cut -d "," -f 2 ;
}

shuffledns_alias(){
	shuffledns -d $1 -r path/to/my-resolvers.txt -w $2 -t 500 -v -o $3/shuffledns.txt;
}


telegram-msg(){ # alias for sending a message to telegram
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
java -noverify -javaagent:burploader.jar -jar -Xmx3G burpsuite_pro_v2020.9.2.jar
}

mscan(){ #runs masscan
sudo masscan -p 4443,2075,2076,6443,3868,3366,8443,8080,9443,9091,3000,8000,5900,8081,6000,10000,8181,3306,5000,4000,8888,5432,15672,9999,161,4044,7077,4040,9000,8089,443,744
}

certspotter(){ 
curl "https://api.certspotter.com/v1/issuances?domain=$1&expand=dns_names" | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u | grep $1
} #h/t Michiel Prins

crtsh(){
curl -s https://crt.sh/?Identity=%.$1 | grep ">*.$1" | sed 's/<[/]*[TB][DR]>/\n/g' | grep -vE "<|^[\*]*[\.]*$1" | sort -u | awk 'NF' | sed 's/\*\.//g'
}

open-url(){

	while read line; 
	do
	    firefox -new-tab -headless "$line";
	    sleep 2s;
	done < $1
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
