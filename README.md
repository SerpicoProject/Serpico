# Serpico
## SimplE RePort wrIting and CollaboratiOn tool
Serpico is a penetration testing report generation and collaboration tool. It was developed to cut down on the amount of time it takes to write a penetration testing report.

Video Demo of Functionality:

[Serpico - Demo 1](https://www.youtube.com/watch?v=G_qYcL4ynSc)

[Additional Video Demos](https://github.com/SerpicoProject/Serpico/wiki#online-demos)

## Installation

The prefered method of installation is from [Releases](https://github.com/SerpicoProject/Serpico/releases) which includes all dependencies in one package. 

To build after cloning the project checkout the simple instructions in [Developer Builds](https://github.com/SerpicoProject/Serpico/wiki/Developer-Build)

Serpico can also be built and run on Windows; [Windows Installation](https://github.com/SerpicoProject/Serpico/wiki/Windows-Installation)

Or with Docker:
[Running Serpico From Docker](https://github.com/SerpicoProject/Serpico/wiki/Running-Serpico-From-Docker)

## Post-Installation Releases : Getting Started

### Kali/Ubuntu/Debian 

Initialize the database:
```
/opt/Serpico/init_serpico.sh
```

And then start Serpico:
```
/opt/Serpico/start_serpico.sh
```

### OS X

Initialize the database:
```
/Users/Shared/Serpico/init_serpico.sh
```

Start Serpico:
```
/Users/Shared/Serpico/start_serpico.sh
```

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
https://github.com/SerpicoProject/Serpico/wiki/Inserting-Screenshots

This is an area we know needs development so e-mail us with any ideas.

See the Wiki for more information, [Serpico Meta-Language In Depth](https://github.com/SerpicoProject/Serpico/wiki/Serpico-Meta-Language-In-Depth)

## Support
- As questions come up we try to add them to the [Wiki](https://github.com/MooseDojo/Serpico/wiki).
- IRC: [#therealserpico](http://webchat.freenode.net/?channels=%23therealserpico&uio=d4) on freenode
- If you have found a bug or would like a new feature, please create an [Issue](https://github.com/SerpicoProject/Serpico/issues/new)
- We offer Enterprise [E-mail Support](https://www.serpicoproject.com/purchase/) for teams of users or template related questions

## GOTCHAS
- Microsoft has a really annoying habit of changing a character for you. Always beware of this when working with the meta language
