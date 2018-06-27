<?php
/**
 * Created by PhpStorm.
 * User: hanxiao
 * Date: 2018/6/27
 * Time: 14:31
 */
include "../include/inc.php";
$font = new Font();
try {
    $font->dispath(ROOT_PATH . 'include/controller/');
} catch (Exception $e) {
    $array = array('code'=>$e->getCode(), 'message'=>$e->getMessage(), 'act'=>$front->getActionName());
    exit($array['message']);
}
