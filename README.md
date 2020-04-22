# Serpico

# April 9th, 2020 - Archiving...

I am currently looking for a new home for Serpico. Until we find a new maintainer and/or company it will remain read only. Thank you so much for 7(!) years with this project. 

## SimplE RePort wrIting and CollaboratiOn tool
Serpico is a penetration testing report generation and collaboration tool. It was developed to cut down on the amount of time it takes to write a penetration testing report.

[Serpico Demo Video](https://www.youtube.com/watch?v=Sj7DkaQyx5o)

[Additional Video Demos](https://github.com/SerpicoProject/Serpico/wiki#online-demo)

## Installation

Getting started in a few commands:

1. Create a working directory for Serpico and change to it:
```
mkdir SERPICO
cd SERPICO
```

2. Pull down the newest version of Serpico:
```
docker run --name serpico -p 8443:8443 \
  -v"$(pwd)/db":/Serpico/db -v"$(pwd)/tmp":/Serpico/tmp \
  -v"$(pwd)/attachments":/Serpico/attachments \
  -it serpico/serpico
```

3. Browse to https://127.0.0.1:8443 and start using it.


More detailed information:

* [Running Serpico From Docker](https://github.com/SerpicoProject/Serpico/wiki/Running-Serpico-From-Docker): The prefered method of installation. 

* [Install Packaged Release](https://github.com/SerpicoProject/Serpico/releases): As of [v1.3.0](https://github.com/SerpicoProject/Serpico/releases/tag/1.3.0) (June 2018) we are no longer creating packaged builds.

* [Developer Build](https://github.com/SerpicoProject/Serpico/wiki/Developer-Build): Simple Instructions to build from clone

* [Windows Developer Build](https://github.com/SerpicoProject/Serpico/wiki/Windows-Installation): Building Serpico from source on Windows; Docker is the easiest installation method.

## About Serpico
Serpico is at its core a report generation tool but targeted at creating information security reports. When building a report the user adds "findings" from the template database to the report. When there are enough findings, click 'Generate Report' to create the docx with your findings. The docx design comes from a Report Template which can be added through the UI; a default one is included. The Report Templates use a custom Markup Language to stub the data from the UI (i.e. findings, customer name, etc) and put them into the report.

## Features
#### Report Template Editing is Easy
**Philosophy: Editing a report template should be easy.**
During peer review we would constantly ran into "little things" we were fixing from the report template; an extra space here, a misspelling there. But it adds up. With Serpico, "fix" the report template, upload it back through the UI, and generate a new report; the error should be fixed permanently.

#### Template Database
**Philosophy: We do not need to write most findings from scratch.**
Most findings have been found in a previous assessment. In Serpico, all authors can pull findings from the template database and add to the report. A user can also 'Upload' a finding they made into the Template Database to share with everyone.

#### Attachment Collaboration
**Philosophy: It should be easy to share files with teammates.**
Use the 'Add Attachment' functionality to store a file (e.g. screenshots, nmap scans) or share with teammates on a pen test. No thumb drive swapping or e-mailing, just log into the UI and download the files. At the end of the assessment everything traded or generated for that assessment is in one place.


## Microsoft Word Meta-Language
The Meta language used for Microsoft Word was designed to be as simple as possible while still serving enough features to create a basic penetration test report.  That being said it has a learning curve (and many bugs) and I _highly_ suggest looking at "Serpico - Report.docx" or "Serpico - No DREAD.docx" and editing these rather than working from scratch.

See also:

* [Serpico Meta-Language In Depth](https://github.com/SerpicoProject/Serpico/wiki/Serpico-Meta-Language-In-Depth)


## Support
* [Wiki](https://github.com/MooseDojo/Serpico/wiki): We try to add most common questions to the wiki.
* [Slack](https://serpicoproject.slack.com)
* [Issue](https://github.com/SerpicoProject/Serpico/issues/new) : If you have found a bug or would like a new feature
* [E-mail Support](https://www.serpicoproject.com/support/): For teams of users or template related questions

