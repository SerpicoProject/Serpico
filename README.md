# Serpico
## SimplE RePort wrIting and CollaboratiOn tool
Serpico is a penetration testing report generation and collaboration tool. It was developed to cut down on the amount of time it takes to write a penetration testing report.

Video Demo of Functionality:

[Serpico - Demo 1](https://www.youtube.com/watch?v=G_qYcL4ynSc)

[Additional Video Demos](https://github.com/MooseDojo/Serpico/wiki#online-demos)

## Installation

### Docker
Serpico has a supported Docker image if you wanted to get started quickly:
[Running Serpico From Docker](https://github.com/MooseDojo/Serpico/wiki/Running-Serpico-From-Docker)

### Building Serpico
Serpico is written in Ruby using Sinatra, Bootstrap, and Haml. Installation should be easy:

- You will need a copy of Ruby. RVM is suggested (https://rvm.io/rvm/install). ruby version 2.1.5 is supported.

```
rvm install 2.1.5
rvm use 2.1.5
```

- If you are running Ubuntu (or also verified on Kali) you will need a couple of dependencies:
```
apt-get install libsqlite3-dev libxslt-dev libxml2-dev zlib1g-dev gcc
```

- Go into Serpico and install the proper gems:
```
cd Serpico
gem install bundler
bundle install
```

- Run the first time script to get setup:
```
ruby scripts/first_time.rb
```

To start using Serpico:
```
ruby serpico.rb
```

Note: A new cert is created on first use. To add your own, just add it to the root directory.

Point your browser to https://127.0.0.1:8443 (or whatever port you assigned) to start using.


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

Inserting Screenshots
https://github.com/MooseDojo/Serpico/wiki/Inserting-Screenshots

This is an area we know needs development so e-mail me with any ideas.

See the Wiki for more information, [Serpico Meta-Language In Depth](https://github.com/MooseDojo/Serpico/wiki/Serpico-Meta-Language-In-Depth)

## Support
- As questions come up we try to add them to the [Wiki](https://github.com/MooseDojo/Serpico/wiki)
- IRC: [#therealserpico](http://webchat.freenode.net/?channels=%23therealserpico&uio=d4) on freenode
- If all else fails create an issue and we will try to get it answered

## GOTCHAS
- Microsoft has a really annoying habit of changing a character for you. Always beware of this when working with the meta language

## Huge Thanks
* Wouldn't exist without testing, support, and feature suggestion of the rest of the [Moosedojo team!](https://github.com/MooseDojo).
* @d4rkd0s for the great logo work. Thanks!
