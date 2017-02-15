#!/usr/bin/php

<?php
    /*
     * fw-scan.php: A firewall utility for various scanning and dictionary attack
     *
     * Copyright (c) 2017 Thi Ha <thiha28.9@gmail.com>
     * All Rights Reserved.
     *
     * This software is released under the terms of the GNU Lesser General Public License v2.1
     * A copy of which is available from http://www.gnu.org/copyleft/lesser.html
     *
     * @version 1.0
     */
  
    define('DEBUG', 1);

    set_time_limit(0);
    
    /*
     * Write log file
     *
     * @param String $message
     */
    function write_log($message)
    {
        global $config, $logfile;
    
        echo "$message";
        
        @file_put_contents($logfile, $message, FILE_APPEND | LOCK_EX);
    }
 
     /*
     * Initialize config file
     *
     * @return Array $config: Config file parameters
     */     
    function init_config()
    {
        $file = 'fw-scan.conf';
        $config = @parse_ini_file($file, TRUE);
        if ($config === FALSE) write_log(getcwd()."/$file missing. Using default parameters.\n");

       if (!isset($config['General']['message_queue']))
        {
            write_log("Message queue paramter missing in the config file\n");
            exit();
        }
        
       if (!isset($config['General']['logdir']))
        {
            write_log("Log directory paramter missing in the config file\n");
            exit();
        }
        
        return $config;
    }
 
     /*
     * Check log message against dictionary
     *
     * @param String $message
     *
     * @return Boolean TRUE || FALSE
     */  
    function dict_check($message)
    {
        global $config;

        $keywords = $config['Keywords']['keywords'];
        foreach($keywords as $uid=>$keyword)
        {
            if (preg_match('/'.$keyword.'/i', $message, $matches))
            {
                if (DEBUG > 0) write_log(__FUNCTION__ . ": Keyword Match Found [$keyword]\n");
                return TRUE;
            }
        }
        
        return FALSE;
    }

     /*
     * Build firewall rule and do variable replacement
     *
     * @param Array  $fwconfig; Firewall configuration information
     * @param Array  $contrack; Array of IP connection information
     *
     * @return String $fwcmd
     */    
    function build_firewall_rule($fwconfig, $contrack)
    {
        $fwcmd = $fwconfig['rule'];
        $fwcmd = str_replace('@SRC_IP',    $contrack['source_ip'], $fwcmd);
        $fwcmd = str_replace('@DST_IP',    $contrack['source_port'], $fwcmd);
        $fwcmd = str_replace('@SRC_PORT',  $contrack['destination_ip'], $fwcmd);
        $fwcmd = str_replace('@Dst_PORT',  $contrack['destination_port'], $fwcmd);
        
        return $fwcmd;
    }
 
    /*
     * Push local firewall rule
     *
     * @param  Array  $fwconfig
     * @param  String $contrack
     */
    function push_local_firewall_rule($fwconfig, $contrack)
    {
        if (!isset($fwconfig['rule'])) return;
        
        $fwcmd = build_firewall_rule($fwconfig, $contrack);
        $rc = exec("$fwcmd > /dev/null 2>&1");
        
        write_log("#$fwcmd\n");
    }
 
    /*
     * Push remote firewall rule
     *
     * @param Array  $fwconfig
     * @param String $contrack
     */ 
    function push_remote_firewall_rule($fwconfig, $contrack)
    {
        if (!isset($fwconfig['host']) || !isset($fwconfig['uanme']) ||
            !isset($fwconfig['pass']) || !isset($fwconfig['rule'])) return;
            
        $remotecmd = "/usr/bin/sshpass -p '{$fwconfig['pass']}' ssh {$fwconfig['uname']}@{$fwconfig['host']}";
        $fwcmd =  build_firewall_rule($fwconfig, $contrack);
        $rc = exec("$remotecmd $fwcmd > /dev/null 2>&1");
        
        write_log("#$fwcmd\n");
    }
    
    /*
     * Push firewall rule
     *
     * @param String $contrack
     */
    function push_firewall_rule($contrack)
    {
        global $config, $blacklist;

        $key = "{$contrack['source_ip']}->{$contrack['destination_ip']}:{$contrack['destination_port']}";
        if (isset($blacklist[$key]))
        {
            $blacklist[$key] .= ',' . $contrack['source_port'];
            if (DEBUG > 0) write_log(__FUNCTION__ . ": Key [$key] Src Ports [{$blacklist[$key]}]\n");
            
            return;
        }
        else
        {
            $blacklist[$key] = $contrack['source_port'];
            if (DEBUG > 0) write_log(__FUNCTION__ . ": Key [$key] Src Ports [{$blacklist[$key]}]\n");
        }
        
        foreach ($config as $uid=>$section)
        {
            if (!isset($section['type']) OR strncasecmp($section['type'], 'firewall', 8) != 0) continue;
            
            if (strncasecmp($section['type'], 'firewall', 8) == 0)
            {
                if (strncasecmp($section['host'], 'localhost', 9) == 0)
                    push_local_firewall_rule($section, $contrack);
                else
                    push_remote_firewall_rule($section, $contrack);
            }
        }
    }
   
    /* 
     * Extract source ip address from log message
     *
     * @param $message
     *
     * @return $ipaddress || NULL
     */
    function extract_src_ipaddr($message)
    {
        $pattern = '/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/';
        
        if (preg_match($pattern, $message, $matches)) return $matches[0];
        
        return NULL;        
    }

    /* 
     * Extract socket information via source ip address
     *
     * @param $source_ip
     */    
    function extract_socket_info($source_ip)
    {
        // Get Src IP, Src Port, Dst IP, Dst Port
        $rc = `netstat -anp | grep $source_ip`;
            
        $lines = explode(PHP_EOL, $rc);
        foreach ($lines as $uid=>$line)
        {
            if (strlen($line) < 10) continue;
            
            $data = preg_split('/\s+/', $line);

            $dst = explode(':', $data[3]);
            $src = explode(':', $data[4]);
            
            if (DEBUG > 0) write_log(__FUNCTION__ . ": Src IP [{$src[0]}] Src Port [{$src[1]}] Dst IP [{$dst[0]}] Dst Port [{$dst[1]}]\n");

            $contrack = Array(  'source_ip'         => $src[0],
                                'source_port'       => $src[1],
                                'destination_ip'    => $dst[0],
                                'destination_port'  => $dst[1]
                             );
            
            return $contrack;
        }
        
        return NULL;
    }

    /* 
     * Process log file
     *
     * @param String $logfile
     *
     * @return Boolean TRUE || FALSE
     */    
    function process_logfile($logfile)
    {
        global $config, $localip;
        
        if (DEBUG > 0)
            $cmd = "/usr/bin/tail -f -n +1 $logfile 2>/dev/null";
        else
            $cmd = "/usr/bin/tail -f $logfile 2>/dev/null";
        
        $fd = popen($cmd, 'r');
        if ($fd === FALSE)
        {
            write_log("Unable to use popen. Parameter: $cmd\n");
            return FALSE;
        }

        while (($line = fgets($fd, 4096)) !== FALSE)
        {
            $message = trim($line);
            
            $rc = dict_check($message);
            if ($rc === FALSE) continue;
            
            $source_ip = extract_src_ipaddr($message);
            if ($source_ip === NULL || $localip == $source_ip) continue;

            $contrack = extract_socket_info($source_ip);
            if ($contrack) push_firewall_rule($contrack);
            
            if (DEBUG > 0) write_log(__FUNCTION__ . ": Logfile [$logfile] Source IP [$source_ip]\n");
        }
        pclose($fd);
        
        return TRUE;
    }
        
    ///
    // Main Code
    $blacklist = Array();
    $config    = init_config();

    $hostname = gethostname();
    $localip  = gethostbyname($hostname);
    
    @mkdir($config['General']['logdir'], 0755, TRUE);
    
    $logfile  = '';
    $services = $config['Services']['logfiles'];
    foreach($services as $uid=>$service)
    {
        // Build Log File
        $logfile = $config['General']['logdir'].'/' . ltrim(str_replace('/', '-', $service), '-');
        
        // Fork of the process
        $pid = pcntl_fork();

        if (!$pid)
        {
            write_log("Processing Log File: $service\n");
            
            if (process_logfile($service) === FALSE) write_log("Enable to process log file: $service\n");
            
            exit($uid);
        }        
    }

    while (pcntl_waitpid(0, $status) != -1) $status = pcntl_wexitstatus($status);
    
    write_log("Shutting Down fw-scan Service.\n");

/*
 * vim:ts=4:sw=4
 */    
?>