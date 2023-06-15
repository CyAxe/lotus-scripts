### Lotus Scripts 🌺📜

Welcome to the official Lotus Lua Scripts repository! Here, we provide a collection of Lua scripts to scan different vulnerabilities.

### Scripting Progress :file_folder:
This table shows the progress of our tool and script development in Lua. We've already rewritten some of our tools, such as the SQLiDetector and Simple SSTI Detector, and we're currently working on several others, including a BugCrowd HunT Framework, a web application scanner, and an SSH bruteforcer.

We're developing scripts for famous CVEs, like CVE-2014-2321, CVE-2019-11248, CVE-2020-11450, and others. We're also working on a scanner for the OWASP Top 10 and a recon Framework.

| Tool/Script                  | Status                       |
| -----------------------------| ----------------------------|
| SQLiDetector                 | :heavy_check_mark: Finished  |
| Simple SSTI Detector         | :heavy_check_mark: Finished  |
| PHPINFO Finder               | :heavy_check_mark: Finished |
| Jenkins /script RCE Scanner          | :heavy_check_mark: Finished  |
| Basic LFI Scanner             | :heavy_check_mark: Finished  |
| BugCrowd HunT Framework      | :hourglass_flowing_sand: In progress        |
| CVE-2014-2321.lua            | :heavy_check_mark: Finished  |
| CVE-2019-11248.lua           | :heavy_check_mark: Finished  |
| CVE-2020-11450.lua           | :heavy_check_mark: Finished  |
| CVE-2022-0378.lua            | :heavy_check_mark: Finished  |
| CVE-2022-0381.lua            | :heavy_check_mark: Finished  |
| CVE-2022-1234.lua            | :hourglass_flowing_sand: In progress |
| SSH Bruteforce               | :hourglass_flowing_sand: In progress |
| CVE-2017-5638 Apache Struts  | :hourglass_flowing_sand: In progress |
| CVE-2017-11882 Microsoft     | :hourglass_flowing_sand: In progress |
| CVE-2018-7600 Drupal         | :hourglass_flowing_sand: In progress |
| CVE-2018-8174 Windows        | :hourglass_flowing_sand: In progress |
| CVE-2019-19781 Citrix        | :hourglass_flowing_sand: In progress |
| CVE-2021-21985 VMware vCenter| :heavy_check_mark: Finished |
| CVE-2023-23752 Joomla! CMS   | :heavy_check_mark: Finished  |
| OWASP Top 10 Scanner         | :hourglass_flowing_sand: In progress |
| Recon Script                 | :hourglass_flowing_sand: In progress |

### Usage 🚀

You can use these scripts as an example or on real targets that you have permission to scan. Please use these scripts responsibly and ethically.
### Installation 🔧

To use the Lotus Lua Scripts, you need to have Lotus installed on your system. You can download from the official Repo: https://github.com/rusty-sec/lotus 🌐

Once you have Lotus installed, you can simply download the scripts from this repository and run them using the following command:

```bash
# target one script
$ lotus scan scriptname.lua -o out.json
# select all scripts in this directory
$ lotus scan active/ -o out.json

```
### Contributing 🤝🏼

We welcome contributions to the Lotus Lua Scripts repository. If you have a script that you would like to contribute, please fork this repository and submit a pull request.

### Disclaimer ⚠️

These scripts are provided for educational purposes only. The authors are not responsible for any damage or illegal activities caused by the misuse of these scripts. Use them at your own risk.
