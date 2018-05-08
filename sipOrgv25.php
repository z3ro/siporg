<?php

# SIPORG v2.5 PORT REPORTER - Free Edition
# co[d]ed by Cold z3ro | HTLover
# https://www.facebook.com/groups/hackteach.org/

error_reporting(0);  
ini_set('Memory_limit','-1');
if( extension_loaded('curl') != true)
{
   die("\e[31mCURL extension is not available on your web server\nTRY:\e[0m sudo apt-get install php-curl \e[31mOR\e[0m sudo apt-get install php7.0-curl\n");
}else{
	if( extension_loaded('pcntl') != true)
	{
		die("\e[31mPCNTL extension is not available on your web server\e[0m\n");
	}else{
		if (!function_exists('pcntl_fork'))
		{		
			die('\e[31mPCNTL functions not available on this PHP installation\e[0m\n');
		}
	}
}
$brutedir = "date_".@date("Y-m-d");

if(!file_exists($brutedir)) { mkdir($brutedir); }
if(!file_exists("./bugged")) { mkdir("./bugged"); }

if (!isset($argv[2]))
{ 
	flag();
	if (empty($argv[1]))
	{
		die("\n Try: php $argv[0] -help\n\n");
	}
	if($argv[1]=="-help" )
	{
		die("\n[*] How to use SIPORG:\n [-] php $argv[0] listips.lst threads\n [-] php $argv[0] ipaddress.lst 100\n [+] Advice for low RAM machines set max threads 500\n\n");
	}
	if(!file_exists($argv[1]))
	{
		die("\n $argv[1] File not Found\n\n");
	}
	die;
}
$list 	= $argv[1]; // listfile
$maxproc= $argv[2]; // max proc
$execute=0;

$w = count(file("$list"));
file_put_contents('sOGrep.htm', '<pre>['.@date("Y/m/d").'] REPORT<br>', FILE_APPEND);
echo "\n[+]TOTLE LOADED : $w HOSTS\n[+]GOODLUCK\n\n"; sleep(5);
foreach (file("$list", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $ipkey => $line) 
{
	//if ( preg_match('/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\:?([0-9]{1,5})?/', $line, $match) ) 
	if (preg_match('/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/', $line, $match))
	{
		if (!filter_var($match[1], FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) 
		{
			break;
		}
		$pid = pcntl_fork();
		$execute++;
		if ($execute >= $maxproc)
		{
			while (pcntl_waitpid(0, $status) != -1) 
			{
				$status = pcntl_wexitstatus($status);
				$execute =0;
				usleep(3000);
				//echo " [$ipkey]  Child $status completed\n";
			}
		}
		
		if (!$pid) 
		{
			$shod_ports = array();
			$nmap_ports = array();
			$notneeded_ports = array(21, 123, 1234, 23, 3306, 5060, 995, 445, 25, 123, 179, 53, 500, 622, 753, 760, 786, 810, 894, 5000, 5001, 975, 69, 22, 465, 587, 993);
			preg_match_all(';[0-9]{1,6}/tcp;', @shell_exec("nmap -sV -T4 -O -F --version-light -Pn --open $match[1]"), $matches);
			//preg_match_all(';[0-9]{1,6}/tcp;', @shell_exec("nmap -Pn --open $match[1]"), $matches);
			foreach ($matches as $value)
			{
				foreach ($value as $port)
				{
					$nmap_ports[] = str_replace('/tcp', '' , $port);
				}
			}

			$shodan = shodan($match[1]);
			foreach(explode(',', $shodan) as $key => $shport)
			{
				$shod_ports[] = trim($shport);
			}
			$our_ports = array(443, 80, 9999, 8080);
			if(!empty($shodan))
			{
				$ports = array_unique(array_merge($our_ports, $shod_ports, $nmap_ports));
			}else{
				$ports = $our_ports;
			}
	
			foreach($ports as $portkey => $requested_port)
			{
				if (!in_array($requested_port, $notneeded_ports))
				{	
					if(preg_match('/443/', $requested_port))
					{
						$scheme= "https";
					}else{
						$scheme= "http";
					}
				
					$result = sIP_Check( $match[1], $scheme, $requested_port);
					if($result)
					{
						
						echo "\e[32m [$ipkey][$portkey]\e[0m \e[31m $match[1]:$requested_port\e[0m | '\e[33;1m $result \e[0m'\n";
					}
				}
			usleep(2000);
			}
		exit;
		}
	}
}


echo "\n\nDONE!. TOTAL $ipkey HOSTS EXECUTED\n";


function sIP_Check( $urls, $scheme='', $request_port='', $path='', $timeout = 10 )
{
	
	if (empty($request_port))
	{
		$url = $scheme."://".$urls.$request_port.$path;
	}else{
		$url = $scheme."://".$urls.":".$request_port.$path;
	}

	$ch = curl_init();
	curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0");
	curl_setopt($ch, CURLOPT_URL, $url);
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
	curl_setopt($ch, CURLOPT_ENCODING, 'gzip,deflate');
	curl_setopt($ch, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	curl_setopt($ch, CURLOPT_AUTOREFERER, true);
	curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
	curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
	curl_setopt($ch, CURLOPT_MAXREDIRS, 3);
	$content  = curl_exec($ch);
	$auth  	  = curl_getinfo($ch , CURLINFO_HTTPAUTH_AVAIL);
	$response = curl_getinfo($ch);
	$url_last = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
	curl_close ($ch);
	if($response['http_code']!="0")
	{
		if($response['url'] != $url)
		{
			$http = parse_url($response['url']);
			$scheme = $http['scheme'];
			$path 	= $http['path'];
			return sIP_Check( $http['host'], $scheme, $http['port'], $path);
		}
		
		$title = trim(getBetween($content,'<title>','</title>'));
		if(empty($title))
		{
			$title = trim(getBetween($content,'<TITLE>','</TITLE>'));
			if(empty($title))
			{
				$title = server_header($url);
				if(trim($title)=="WebServer")
				{
					$title =" Avaya";
				}else{
					if (
					preg_match("/window\.location\.replace\('(.*)'\)/i", $content, $value) || 
					preg_match("/window\.location\.replace\(\"(.*)\"\)/i", $content, $value) || 
					preg_match("/window\.location\=\"(.*)\"/i", $content, $value) || 
					preg_match("/window\.location\='(.*)'/i", $content, $value) || 
					preg_match("/window\.location \=\"(.*)\"/i", $content, $value) || 
					preg_match("/window\.location \='(.*)'/i", $content, $value) || 
					preg_match("/location\.href=\"(.*)\"/i", $content, $value) || 
					preg_match("/location\.href='(.*)'/i", $content, $value) || 
					preg_match("/window\.open\('(.*)',/i", $content, $value) || 
					preg_match("/window\.open\(\"(.*)\",/i", $content, $value) || 
					preg_match("/top\.location\=\"(.*)\"/i", $content, $value) || 
					preg_match("/top\.location\='(.*)'/i", $content, $value) || 
					preg_match("/content\=\"0; url\=(.*)\"/i", $content, $value) ||
					preg_match("/content\='0; url\=(.*)'/i", $content, $value) ||
					preg_match("/frame src\=\"(.*)\"/i", $content, $value) ||
					preg_match("/frame src\='(.*)'/i", $content, $value))
					{
						$httpx = parse_url(str_replace('..','',$value[1]));
						if($httpx['host']=="")
						{
							$http = parse_url($url.str_replace('..','',$value[1]));	
						}else{
							$http = parse_url(str_replace('..','',$value[1]));	
						}
						$scheme = $http['scheme'];
						$path 	= $http['path'];
						return sIP_Check( $http['host'], $scheme, $http['port'], $path);
					}
				}
			}	
		}

		//return array($response['http_code'],$title);
		if(!empty($title))
		{
			if(preg_match('/Polycom/', $title))
			{
				$dir= $GLOBALS['brutedir']."/polycom";
				if(!file_exists($dir) ){ mkdir($dir); }
				$path_burte= $dir. "/". $urls;
				$fp = file_put_contents($path_burte, $url);
				
				$head_server_title = server_header($url);
				if(preg_match("/SoundPoint IP Telephone/i", $head_server_title))
				{ 
					//Polycom SoundPoint IP Telephone
					$newtitle = $title." | <font color='#ee42f4'>PolycomSPIT</font>";
					$msg = '<tr><th scope="row"><a href="'.$url.'" target="_blank">'.$url.'</a></th><td><font color=green> '. $newtitle .'</font> | <a href="./bruter.php?path='.file_get_contents($path_burte).'&type=polycomSPIT&l=1" target="_blank">[BruteMe]</a></td></tr>';
				}else{
					//Server: Restlet-Framework/2.1.7
					if(preg_match("/Restlet/i", server_header(url_base($url) . "/rest/session")))
					{ 
						$newtitle = $title ." | PolycomRestlet";
						$msg = '<tr><th scope="row"><a href="'.$url.'" target="_blank">'.$url.'</a></th><td><font color=green> '. $newtitle .'</font> | <a href="./bruter.php?path='.file_get_contents($path_burte).'&type=polycomRT&l=1" target="_blank">[BruteMe]</a></td></tr>';
					}else{
						//Server: lighttpd
						if(preg_match("/lighttpd/", $head_server_title) && preg_match("/GetCurrentPageName/i", $title))
						{ 
							$title = "Polycom OLD";
							$msg = '<tr><th scope="row"><a href="'.$url.'" target="_blank">'.$url.'</a></th><td><font color=green> '. $title .'</font> | <a href="./bruter.php?path='.file_get_contents($path_burte).'&type=polycomOLD&l=1" target="_blank">[BruteMe]</a></td></tr>';
						}else{
							$msg = '<tr><th scope="row"><a href="'.$url.'" target="_blank">'.$url.'</a></th><td><font color=green> '. $title .'</font></td></tr>';
						}
					}
				}
				
				if($fp){ file_put_contents('sOGrep.htm', $msg .'<br>', FILE_APPEND);}
				return $title;
				
			}
			if(preg_match('/D-Link/', $title))
			{
				$msg = '<tr><th scope="row"><a href="'.$url.'" target="_blank">'.$url.'</a></th><td><font color=green> '. $title .'</font><a href="https://www.exploit-db.com/papers/30061/" target="_blank"><font color=red> D-Link Bugs</font></a></td></tr>';
				file_put_contents('sOGrep.htm', $msg .'<br>', FILE_APPEND);
				return $title;
			}
			if(preg_match('/Vigor/', $title))
			{
				$dir= $GLOBALS['brutedir']."/vigor";
				if(!file_exists($dir) ){ mkdir($dir); }
				
				$path_burte= $dir. "/". $urls;
				$fp = file_put_contents($path_burte, $url);
				if($fp)
				{	
					$msg = '<tr><th scope="row"><a href="'.$url.'" target="_blank">'.$url.'</a></th><td><font color=green> '. $title .'</font> | <a href="./bruter.php?path='.file_get_contents($path_burte).'&type=vigor" target="_blank">[BruteMe]</a></td></tr>';
					file_put_contents('sOGrep.htm', $msg .'<br>', FILE_APPEND);
					return $title;
				}
			}
			if($response['http_code']=="401")
			{

				if($auth=="1")
				{
					
					$dir= $GLOBALS['brutedir']."/auth1";
					if(!file_exists($dir) ){ mkdir($dir); }
					
					$path_burte= $dir. "/". $urls;
					$fp = file_put_contents($path_burte, $url);
					if($fp)
					{	
						$msg = '<tr><th scope="row"><a href="'.$url.'" target="_blank">'.$url.'</a></th><td><font color=green> '. $title .'</font> | <a href="./bruter.php?path='.file_get_contents($path_burte).'&type=basic" target="_blank">[BruteMe]</a></td></tr>';
						file_put_contents('sOGrep.htm', $msg .'<br>', FILE_APPEND);
						return $title;
					}
				}
			
				if($auth=="2")
				{
					$dir= $GLOBALS['brutedir']."/auth2";
					if(!file_exists($dir) ){ mkdir($dir); }
					
					$path_burte= $dir. "/". $urls;
					$fp = file_put_contents($path_burte, $url);
					if($fp)
					{
						$msg = '<tr><th scope="row"><a href="'.$url.'" target="_blank">'.$url.'</a></th><td><font color=green> '. $title.'</font> | <a href="./bruter.php?path='.file_get_contents($path_burte).'&type=digest" target="_blank">[BruteMe]</a></td></tr>';
						file_put_contents('sOGrep.htm', $msg .'<br>', FILE_APPEND);
						return $title;
					}
				}
			}
			if (preg_match("/VoIP Gateway/", $title))
			{
				$dir= $GLOBALS['brutedir']."/voipgateway";
				if(!file_exists($dir) ){ mkdir($dir); }
				
				$path_burte= $dir. "/". $urls;
				$fp = file_put_contents($path_burte, $url);
				if($fp)
				{	
					$msg = '<tr><th scope="row"><a href="'.$url.'" target="_blank">'.$url.'</a></th><td><font color=green> '. $title .'</font> | <a href="./voipgatewaybrute.php?path='.file_get_contents($path_burte).'" target="_blank">[BruteMe]</a></td></tr>';
					file_put_contents('sOGrep.htm', $msg .'<br>', FILE_APPEND);
					return $title;
				}
			}
			if($title)
			{
				$msg = '<tr><th scope="row"><a href="'.$url.'" target="_blank">'.$url.'</a></th><td><font color=green> '.$title.'</font></td></tr>';
				file_put_contents('sOGrep.htm', $msg .'<br>', FILE_APPEND);
				return $title;
			}
		}else{
			if($response['http_code']!="0")
			{	
				$textinside = trim(str_replace(" ", "",str_replace("\n", "",substr(strip_tags($content), 0, 20))));
				
				$msg = '<tr><th scope="row"><a href="'.$url.'" target="_blank">'.$url.'</a></th><td><font color=green>UNKNOWN</font> | '.$textinside.'</td></tr>';
				file_put_contents('sOGrep.htm', $msg .'<br>', FILE_APPEND);
				return " UNKNOWN| ".$textinside;
			}
			if($response['http_code']=="404")
			{
				$msg = '<tr><th scope="row"><a href="'.$url.'" target="_blank">'.$url.'</a></th><td><font color=blue>ERR404</font></td></tr>';
				file_put_contents('sOGrep.htm', $msg .'<br>', FILE_APPEND);
				return " 404ERR";
			}
		}
	}
}
function url_base($url)
{
	$http = parse_url($url);
	if(!$http['port'])
	{
		$url = $http['scheme']."://".$http['host'];
	}else{
		$url = $http['scheme']."://".$http['host'].":".$http['port'];
	}
	return $url;
}
function shodan($host, $timeout = 4 )
{
	$ch = curl_init();
	curl_setopt( $ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0" );
	curl_setopt( $ch, CURLOPT_URL, 'https://www.shodan.io/host/'.$host );
	curl_setopt( $ch, CURLOPT_SSL_VERIFYHOST, 0);
	curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, 0);
	curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
	curl_setopt( $ch, CURLOPT_CONNECTTIMEOUT, $timeout );
	curl_setopt( $ch, CURLOPT_TIMEOUT, $timeout );
	$content = curl_exec( $ch );
	return getBetween($content, 'content="Ports open:', '" />');
}

function getBetween($content, $start, $end)
{
	$r = explode($start, $content);
	if (isset($r[1]))
	{
		$r = explode($end, $r[1]);
		return $r[0];
	}
	return '';
}

function server_header($url)
{
	stream_context_set_default( [
		'ssl' => [
		'verify_peer' => false,
		'verify_peer_name' => false,
		],
	]);
	
	$headers = @get_headers($url);
	if (isset($headers[1]))
	{
		foreach( $headers as $value )
		{
			if (strpos($value, 'Server:') !== false) 
			{
				return str_replace("Server:","",$value);
			}
		}
	}
}

function flag()
{
	print"\e[32m
	 ____  ___  ____    ___   ____    ____ 
	/ ___||_ _||  _ \  / _ \ |  _ \  / ___|
	\___ \ | | | |_) || | | || |_) || |  _ 
	 ___) || | |  __/ | |_| ||  _ < | |_| |  \e[0m\e[31mv2.5 Free\e[0m\e[32m
	|____/|___||_|     \___/ |_| \_\ \____| 
				\e[0m[+] PORT REPORTER
				[+] One of HTLovers collection\n\n";
}
?>
