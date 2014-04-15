# Serpico
## SimplE RePort wrIting and CollaboratiOn tool
Serpico is a penetration testing report generation and collaboration tool. It was developed to cut down on the amount of time it takes to write a penetration testing report. 

## Installation
Serpico is written in Ruby using Sinatra, Bootstrap, and Haml. Installation should be easy:

1. You will need a copy of Ruby. RVM is suggested, but ruby1.9.3 on Ubuntu is fine also.

2. If you are running Ubuntu (or also verified on Kali) you will need a couple of dependencies:
```
apt-get install libsqlite3-dev libxslt-dev libxml2-dev
```

3. Finally install the proper gems:
```
gem install bundler
bundle install
```
4. Run the first time script to get setup:
```
ruby scripts/first_time.rb
```

To start using Serpico:
```
ruby serpico.rb
```

Note: A new cert is created on first use. To add your own, just add it to the root directory.

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
The Meta language used for Microsoft Word was designed to be as simple as possible while still serving enough features to create a basic penetration test report.  That being said it has a learning curve (and many bugs) and I _highly_ suggest looking at "Serpico - Report.docx" or "Serpico - Kitchen Sink.docx" and editing these rather than working from scratch.

This is an area we know needs development so e-mail me with any ideas.

### Meta language In-Depth
Here is the list of characters used:

_Ω_ - A simple substitution variable.

```
ΩFULL_COMPANY_NAMEΩ

renders as:
Acme Corporation
```

_¬_ - for each
```
¬finding¬
STUFF
∆

Renders as a for loop for every finding and prints 'STUFF' inbetween. 
```

_π_ - Substituition variable inside of for loops. Do not use Ω inside of a for loop.

```
¬report/findings_list/findings¬
πtitleπ
∆

Renders the finding title for every finding in the findings_list of the report.
```

_æ_ - for each loop for table rows only
_:::_ - is used for if statements within the row
```
æreport/findings_list/findings:::DREAD_TOTAL>35æ

Renders a new table row every finding with a DREAD total greater than 35.
```

_∞_ - Substituition variable inside of a for loop inside of a table. Only used in a table.
```
æreport/findings_list/findings:::DREAD_TOTAL>35æ ∞title∞

Renders a new table row with the title for every finding with a DREAD total greater than 35.
```

_†_ - if conditional
```
† DREAD_SCORE > 1 †
HELLO WORLD
¥

Renders a HELLO WORLD if the DREAD_SCORE is > 1
```

_µ_ - Initiates choose/when structure
_ƒ_ - The when value in a choose/when
_å_ - Ends the choose/when not in a for-each
_≠- - Ends the choose/when inside of a for-each

```
¬overview/paragraph¬ 
µCONDITIONALµ π.π
ƒcodeƒ π.π
ƒitalicsƒ π.π
÷ π.π ≠

This will take each paragraph from the overview section of the finding. If the paragraph is labelled as code then the paragraph will be formatted as code. The "." above means the paragraph variable from the 'overview/paragraph' for loop. 

```

## GOTCHAS
- Microsoft has a really annoying habit of changing a character for you. Always beware of this when working with the meta language

## Huge Thanks
Wouldn't exist without testing, support, and feature suggestion of the rest of the [Moosedojo team!](https://github.com/MooseDojo).

