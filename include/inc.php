<?php
/**
 * Created by PhpStorm.
 * User: hanxiao
 * Date: 2018/6/27
 * Time: 15:18
 */
define('ROOT_PATH', substr(__DIR__, 0, -7));
function autoload($class) {
    if (!class_exists($class)) {
        if (strpos($class, 'Controller') !== false) {
            include ROOT_PATH . "include/controller/{$class}.php";
        }
    }
}

spl_autoload_register('autoload');

include ROOT_PATH . 'plugin/vendor/autoload.php';

class Font
{
    private $controlName;
    private $actionName;

    public function __construct()
    {
        $this->controlName = !empty($_REQUEST['c']) ? ucfirst(trim($_REQUEST['c'])) : 'Web';
        $this->actionName     = !empty($_REQUEST['a']) ? trim($_REQUEST['a']) : 'index';
    }

    public function dispath($controlPath)
    {
        $controller = $this->controlName . 'Controller';
        if (file_exists($controlPath . $controller . '.php')) {
            $controlObj = new $controller($this->controlName, $this->actionName);
            $action = $this->actionName;
            if (method_exists($controlObj, $action)) {
                $controlObj->$action();
            } else {
                Display_javascript('', '/');

            }
        } else {
            Display_javascript('', '/');
        }
    }

    public function getControlName()
    {
        return $this->controlName;
    }

    public function getActionName()
    {
        return $this->actionName;
    }
}

include ROOT_PATH . 'include/func.php';