<?php

/**
 * 获取客户端IP地址
 * @param boolean $pasportlogin 是否是passport登录
 * @param boolean $forwarded 是否取HTTP_X_FORWARDED_FOR
 * @return string
 */
function Get_Client_ip($pasportlogin = true, $forwarded = false)
{
    if (getenv("HTTP_X_REAL_IP") && strcasecmp(getenv("HTTP_X_REAL_IP"), "unknown") && !$forwarded) {
        $ip = getenv("HTTP_X_REAL_IP");
    } else if (getenv("HTTP_CLIENT_IP") && strcasecmp(getenv("HTTP_CLIENT_IP"), "unknown")) {
        $ip = getenv("HTTP_CLIENT_IP");
    } else if (getenv("HTTP_X_FORWARDED_FOR") && strcasecmp(getenv("HTTP_X_FORWARDED_FOR"), "unknown")) {
        $ip = getenv("HTTP_X_FORWARDED_FOR");
    } else if (getenv("REMOTE_ADDR") && strcasecmp(getenv("REMOTE_ADDR"), "unknown")) {
        $ip = getenv("REMOTE_ADDR");
    } else if (isset($_SERVER['REMOTE_ADDR']) && $_SERVER['REMOTE_ADDR'] && strcasecmp($_SERVER['REMOTE_ADDR'], "unknown")) {
        $ip = $_SERVER['REMOTE_ADDR'];
    } else {
        $ip = "unknown";
    }

    if ($pasportlogin === true) {
        if (false !== strpos($ip, ',')) {
            $arrIp = explode(', ', $ip);
            for ($i = 0; $i < count($arrIp); $i++) {
                if (!preg_match("/^(10|172\.16|192\.168\.)/", $arrIp[$i])) {
                    $ip = $arrIp[$i];
                    break;
                }
            }
        }
    }

    return ($ip);
}

/**
 * 获取客户端端口地址
 *
 * @return int/false
 */
function Get_Client_port()
{
    //此字段是运维设置的，由前端逐级向后传递
    if (isset($_SERVER['HTTP_REMOTE_X_PORT']) && $_SERVER['HTTP_REMOTE_X_PORT'] > 0) {
        return intval($_SERVER['HTTP_REMOTE_X_PORT']);
    } elseif (isset($_SERVER['REMOTE_PORT']) && $_SERVER['REMOTE_PORT'] > 0) {
        return intval($_SERVER['REMOTE_PORT']);
    } else {
        return false;
    }
}

/**
 * 获取服务器ip
 * @param boolean $ip2long 是否需要ip2long转化
 * @return string
 */
function Get_Server_ip($ip2long = false)
{
    $serverip = '';

    if (__IS_WIN__ == 0) {
        //优先获取外网ip
        $line = '/sbin/ifconfig | sed -n -e \'/eth/{N;p}\' | awk \'BEGIN{FS=":"}/inet addr/{print $2}\' | awk \'{print $1}\' | sed \'/192/d\' | head -1';
        $serverip = trim(exec($line));

        //如果为空，再获取内网ip
        if ($serverip == '') {
            $line = '/sbin/ifconfig | sed -n -e \'/eth/{N;p}\' | awk \'BEGIN{FS=":"}/inet addr/{print $2}\' | awk \'{print $1}\' | head -1';
            $serverip = trim(exec($line));
        }
    } else {
        $line = 'ipconfig';
        exec($line, $output);
        $my_reg_expr = "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$";
        foreach ($output as $row) {
            if (false !== strpos($row, 'IP Address')) {
                preg_match('/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/', $row, $matches);
                if (isset($matches[0])) {
                    $serverip = $matches[0];
                    break;
                }
            }
        }
    }

    //如果还没有就给个默认值吧
    if ($serverip == '') {
        $serverip = '127.0.0.1';
    }

    if ($ip2long === true) {
        return abs(ip2long($serverip));//兼容32位
    } else {
        return $serverip;
    }
}

/**
 * 输出跳转js
 * @param string $str 消息提示
 * @param string $location 地址
 * @param boolean $istop 是否停止
 * @param boolean $norand 是否不携带随机参数
 * @return null
 */
function Display_javascript($str, $location = 'history.back', $istop = false, $norand = false)
{
    header("Cache-Control: max-age=0");
    header('Expires: Mon, 26 Jul 1997 05:00:00 GMT');
    header('Last-Modified: ' . gmdate('D, d M Y H:i:s') . ' GMT');
    header('Cache-Control: post-check=0, pre-check=0', false);
    header('Pragma: no-cache'); //兼容http1.0和https

    $html = "<!DOCTYPE HTML><html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=gbk\"><script language=\"javascript\">\n";
    if (strlen($str) > 0) {
        $html .= "alert(\"$str\");\n";
    }
    if ($location == "history.back") {
        $html .= "window.history.back(-1);\n";
    } elseif ($location == "reload") {
        $html .= "window.location.reload();\n";
    } elseif ($location == 'close') {
        $html .= "window.close();\n";
    } else {
        if (!$norand) {
            if (strstr($location, "?") === false) {
                $location .= "?rand=" . rand();
            } else {
                $location .= "&rand=" . rand();
            }
        }
        if ($istop) {
            $html .= "parent.document.location.href=\"$location\";\n";
        } else {
            $html .= "window.location.href=\"$location\";\n";
            //如果传入的字符串是空，用301条转
            if (strlen(trim($str)) == 0) {
                header('Location: ' . $location);
                exit();
            }
        }
    }
    $html .= "</script></head></html>";
    echo $html;
    exit();
}

/**
 * 64位整型
 * @param bigint $bigint 整型变量
 * @return bigint
 */
function bigintval($bigint)
{
    $bigint = filter_var($bigint, FILTER_SANITIZE_NUMBER_INT);

    if ($bigint === "") {
        return false;
    } else {
        return $bigint;
    }
}

/**
 * 兼容新版本的htmlspecialchars
 * @param  string $string 字符串
 * @param  string $encoding 编码
 * @return string
 */
function Htmlspecialchars_For_php54($string, $encoding = 'ISO-8859-1')
{
    if (version_compare(PHP_VERSION, '5.4.0', '<')) {
        return htmlspecialchars($string);
    } else {
        return htmlspecialchars($string, ENT_COMPAT | ENT_HTML401, $encoding);
    }
}

/**
 * 过滤$_GET,$_POST参数
 * @return NULL
 */
function fliterData()
{
    if (!isset($_POST['editorcontent'])) {
        $_GET = array_map('strip_tags', $_GET);
        $_POST = array_map('strip_tags', $_POST);
        $_GET = array_map('Htmlspecialchars_For_php54', $_GET);
        $_POST = array_map('Htmlspecialchars_For_php54', $_POST);
        $tempget = array();
        foreach ($_GET as $k_g => $v_g) {
            $t_k_g = strip_tags($k_g);
            $t_k_g = Htmlspecialchars_For_php54($t_k_g);
            if (trim($t_k_g) == "" || trim($k_g) !== trim($t_k_g)) {
                unset($_GET[$k_g]);
            } else {
                $tempget[$k_g] = $v_g;
            }
        }
        if (count($tempget) > 0) {
            $_GET = $tempget;
        }
        $temppost = array();
        foreach ($_POST as $k_p => $v_p) {
            $t_k_p = strip_tags($k_p);
            $t_k_p = Htmlspecialchars_For_php54($t_k_p);
            if (trim($t_k_p) == "" || trim($k_p) !== trim($t_k_p)) {
                unset($_POST[$k_p]);
            } else {
                $tempget[$k_p] = $v_p;
            }
        }
        if (count($temppost) > 0) {
            $_POST = $temppost;
        }
    } else {
        $temp_editorcontent = $_POST['editorcontent'];
        $_GET = array_map('strip_tags', $_GET);
        $_POST = array_map('strip_tags', $_POST);
        $_GET = array_map('Htmlspecialchars_For_php54', $_GET);
        $_POST = array_map('Htmlspecialchars_For_php54', $_POST);
        $tempget = array();
        foreach ($_GET as $k_g => $v_g) {
            $t_k_g = strip_tags($k_g);
            $t_k_g = Htmlspecialchars_For_php54($t_k_g);
            if (trim($t_k_g) == "" || trim($k_g) !== trim($t_k_g)) {
                unset($_GET[$k_g]);
            } else {
                $tempget[$k_g] = $v_g;
            }
        }
        if (count($tempget) > 0) {
            $_GET = $tempget;
        }
        $temppost = array();
        foreach ($_POST as $k_p => $v_p) {
            $t_k_p = strip_tags($k_p);
            $t_k_p = Htmlspecialchars_For_php54($t_k_p);
            if (trim($t_k_p) == "" || trim($k_p) !== trim($t_k_p)) {
                unset($_POST[$k_p]);
            } else {
                $tempget[$k_p] = $v_p;
            }
        }
        if (count($temppost) > 0) {
            $_POST = $temppost;
        }
        $_POST['editorcontent'] = strip_tags($temp_editorcontent, '<p><a><strong><em><span><a><img><br>');
    }
}

/**
 * 检测/过滤字符串XSS注入
 * @param string $val 输入字符串（数字类型请用intval或者floatval转换处理）
 * @param boolean $onlycheck 是否仅检测（true:仅检测，返回结果为boolean; 默认:返回过滤字符串）
 * @param string $allowable_html_tags 允许的html标签（'none':清除全部html标签; '<p><a>':保留p和a标签，同strip_tags第二个参数; 默认:不做处理）
 * @param boolean $htmlspecialchars 是否使用htmlspecialchars函数处理返回结果（ture:使用;默认:不使用）
 * @return mix
 */
function removeXSS($val, $onlycheck = false, $allowable_html_tags = '', $htmlspecialchars = false)
{
    $isdangerous = false;

    //如果设置了过滤全部html标签，则过滤全部标签
    if ($allowable_html_tags == 'none') {
        $val = strip_tags($val);
    } elseif ($allowable_html_tags != '') {
        $val = strip_tags($val, $allowable_html_tags);
    }//如果设置了可使用的html标签，则保留这部分标签


    $val = preg_replace('/([\x00-\x08,\x0b-\x0c,\x0e-\x19])/', '', $val);
    $search = 'abcdefghijklmnopqrstuvwxyz';
    $search .= 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $search .= '1234567890!@#$%^&*()';
    $search .= '~`";:?+/={}[]-_|\'\\';
    for ($i = 0; $i < strlen($search); $i++) {
        $val = preg_replace('/(&#[xX]0{0,8}' . dechex(ord($search[$i])) . ';?)/i', $search[$i], $val);
        $val = preg_replace('/(&#0{0,8}' . ord($search[$i]) . ';?)/', $search[$i], $val);
    }
    $ra1 = array('javascript', 'vbscript', 'expression', 'applet', 'meta', '<xml', '&lt;xml', '&#60;xml', 'blink', 'link', 'style', 'script', 'embed', 'object', 'iframe', 'frame', 'frameset', 'ilayer', 'layer', 'bgsound', 'title', 'base');
    $ra2 = array('onabort', 'onactivate', 'onafterprint', 'onafterupdate', 'onbeforeactivate', 'onbeforecopy', 'onbeforecut', 'onbeforedeactivate', 'onbeforeeditfocus', 'onbeforepaste', 'onbeforeprint', 'onbeforeunload', 'onbeforeupdate', 'onblur', 'onbounce', 'oncellchange', 'onchange', 'onclick', 'oncontextmenu', 'oncontrolselect', 'oncopy', 'oncut', 'ondataavailable', 'ondatasetchanged', 'ondatasetcomplete', 'ondblclick', 'ondeactivate', 'ondrag', 'ondragend', 'ondragenter', 'ondragleave', 'ondragover', 'ondragstart', 'ondrop', 'onerror', 'onerrorupdate', 'onfilterchange', 'onfinish', 'onfocus', 'onfocusin', 'onfocusout', 'onhelp', 'onkeydown', 'onkeypress', 'onkeyup', 'onlayoutcomplete', 'onload', 'onlosecapture', 'onmousedown', 'onmouseenter', 'onmouseleave', 'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup', 'onmousewheel', 'onmove', 'onmoveend', 'onmovestart', 'onpaste', 'onpropertychange', 'onreadystatechange', 'onreset', 'onresize', 'onresizeend', 'onresizestart', 'onrowenter', 'onrowexit', 'onrowsdelete', 'onrowsinserted', 'onscroll', 'onselect', 'onselectionchange', 'onselectstart', 'onstart', 'onstop', 'onsubmit', 'onunload');
    $ra = array_merge($ra1, $ra2);
    $found = true;
    while ($found == true) {
        $val_before = $val;
        for ($i = 0; $i < sizeof($ra); $i++) {
            $pattern = '/';
            for ($j = 0; $j < strlen($ra[$i]); $j++) {
                if ($j > 0) {
                    $pattern .= '(';
                    $pattern .= '(&#[xX]0{0,8}([9ab]);)';
                    $pattern .= '|';
                    $pattern .= '|(&#0{0,8}([9|10|13]);)';
                    $pattern .= ')*';
                }
                $pattern .= $ra[$i][$j];
            }
            $pattern .= '/i';
            $replacement = substr($ra[$i], 0, 2) . '<x>' . substr($ra[$i], 2);
            $val = preg_replace($pattern, $replacement, $val);
            if ($val_before == $val) {
                $found = false;
            } else {
                $isdangerous = true;
            }
        }
    }

    if ($onlycheck === false) {
        if ($htmlspecialchars === false) {
            return $val;
        } else {
            return Htmlspecialchars_For_php54($val);
        }
    } else {
        return $isdangerous;
    }
}

/**
 * 可逆的字符串加密函数
 * @param int $txtStream 待加密的字符串内容
 * @param int $password 加密密码
 * @return string 加密后的字符串
 */
function encrystr($txtStream, $password = '58al92bl')
{
    //密锁串，不能出现重复字符，内有A-Z,a-z,0-9,/,=,+,_,
    $lockstream = 'st=lDEFABCNOPyzghi_jQRST-UwxkVWXYZabcdef+IJK6/7nopqr89LMmGH012345uv';
    //随机找一个数字，并从密锁串中找到一个密锁值
    $lockLen = strlen($lockstream);
    $lockCount = rand(0, $lockLen - 1);
    $randomLock = $lockstream[$lockCount];
    //结合随机密锁值生成MD5后的密码
    $password = md5($password . $randomLock);
    //开始对字符串加密
    $txtStream = base64_encode($txtStream);
    $tmpStream = '';
    $i = 0;
    $j = 0;
    $k = 0;
    for ($i = 0; $i < strlen($txtStream); $i++) {
        $k = ($k == strlen($password)) ? 0 : $k;
        $j = (strpos($lockstream, $txtStream[$i]) + $lockCount + ord($password[$k])) % ($lockLen);
        $tmpStream .= $lockstream[$j];
        $k++;
    }
    return $tmpStream . $randomLock;
}

/**
 * 可逆的字符串解密函数
 * @param int $txtStream 待加密的字符串内容
 * @param int $password 解密密码
 * @return string 解密后的字符串
 */
function decryptstr($txtStream, $password = '58al92bl')
{
    //密锁串，不能出现重复字符，内有A-Z,a-z,0-9,/,=,+,_,
    $lockstream = 'st=lDEFABCNOPyzghi_jQRST-UwxkVWXYZabcdef+IJK6/7nopqr89LMmGH012345uv';

    $lockLen = strlen($lockstream);
    //获得字符串长度
    $txtLen = strlen($txtStream);
    //截取随机密锁值
    $randomLock = $txtStream[$txtLen - 1];
    //获得随机密码值的位置
    $lockCount = strpos($lockstream, $randomLock);
    //结合随机密锁值生成MD5后的密码
    $password = md5($password . $randomLock);
    //开始对字符串解密
    $txtStream = substr($txtStream, 0, $txtLen - 1);
    $tmpStream = '';
    $i = 0;
    $j = 0;
    $k = 0;
    for ($i = 0; $i < strlen($txtStream); $i++) {
        $k = ($k == strlen($password)) ? 0 : $k;
        $j = strpos($lockstream, $txtStream[$i]) - $lockCount - ord($password[$k]);
        while ($j < 0) {
            $j = $j + ($lockLen);
        }
        $tmpStream .= $lockstream[$j];
        $k++;
    }
    return base64_decode($tmpStream);
}

/* End of file func.php */
