/* Copyright (c) 2015, Chandan B.N.
 *
 * Copyright (c) 2015, FIRST.ORG, INC

 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 *    following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
 *    products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


 * Forked by Willis Vandevanter, modified for CVSSv2
 */

/*

CVSSjs Version 0.1 beta

Usage:
    craete an html element with an id for eg.,
    <div id="cvssboard"></div>

    // create a new instance of CVSS calculator:
    var c = new CVSS.js("cvssboard");

    // create a new instance of CVSS calculator with some event handler callbacks
    var c = new CVSS.js("cvssboard", {
                onchange: function() {....} //optional
                onsubmit: function() {....} //optional
                }

    // set a vector
    c.set('AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L');

    //get the value
    c.get() returns an object like:

    {
        score: 4.3,
        vector: 'AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L'
    }

*/

var CVSS = CVSS || {};
CVSS.js = function (id, options) {
    this.options = options;
    this.wId = id;
    var e = function (tag) {
        return document.createElement(tag);
    };

    // Base Group
    this.bg = {
        AV: 'Attack Vector',
        AC: 'Attack Complexity',
        AU: 'Authentication',
        C: 'Confidentiality',
        I: 'Integrity',
        A: 'Availability'
    };

    // Base Metrics
    this.bm = {
        AV: {
            N: {
                l: 'Network',
                d: "<b>Worst:</b> A vulnerability exploitable with network access means the vulnerable authorization scope is bound to the network stack and the attacker's path to the vulnerable system is at the network layer. Such a vulnerability is often termed 'remotely exploitable'."
            },
            A: {
                l: 'Adjacent Network',
                d: "<b>Worse:</b> A vulnerability exploitable with adjacent network access means the vulnerable authorization scope is bound to the network stack and the attacker's path to the vulnerable system is at the data link layer. Examples include local IP subnet, Bluetooth, IEEE 802.11, and local Ethernet segment."
            },
            L: {
                l: 'Local',
                d: "<b>Bad:</b> A vulnerability exploitable with local access means the vulnerable authorization scope is not bound to the network stack and the attacker's path to the vulnerable authorization scope is via read / write / execute capabilities. If the attacker has the necessary Privileges Required to interact with the vulnerable authorization scope, they may be logged in locally; otherwise, they may deliver an exploit to a user and rely on User Interaction"
            }
        },
        AC: {
            L: {
                l: 'Low',
                d: "<b>Worst:</b> Specialized access conditions or extenuating circumstances do not exist. An attacker can expect repeatable exploit success against a vulnerable target."
            },
            M: {
                l: 'Medium',
                d: "<b>Worse:</b> Conditions somewhat specialized."
            },
            H: {
                l: 'High',
                d: "<b>Bad:</b> A successful attack depends on conditions outside the attacker's control. That is, a successful attack cannot be accomplished at-will, but requires the attacker to invest in some measurable amount of effort in preparation or execution against a specific target before successful attack can be expected. A successful attack depends on attackers overcoming one OR both of the following conditions: the attacker must gather target-specific reconnaissance; or the attacker must prepare the target environment to improve exploit reliability."
            }
        },
        AU: {
            N: {
                l: 'None',
                d: "<b>Worst:</b> The attacker is unprivileged or unauthenticated."
            },
            S: {
                l: 'Single',
                d: "<b>Worse</b> The attacker is authenticated with privileges that provide basic, low-impact capabilities. With these starting privileges an attacker is able to cause a Partial impact to one or more of: Confidentiality, Integrity, or Availability. Alternatively, an attacker with Low privileges may have the ability to cause an impact only to non-sensitive resources."
            },
            M: {
                l: 'Multiple',
                d: "<b>Bad:</b> The attacker is authenticated with privileges that provide significant control over component resources. With these starting privileges an attacker can cause a Complete impact to one or more of: Confidentiality, Integrity, or Availability. Alternatively, an attacker with High privileges may have the ability to cause a Partial impact to sensitive resources."
            }
        },
        C: {
            C: {
                l: 'Complete',
                d: "<b>Worst:</b> There is total information disclosure, resulting in all resources in the affected scope being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact to the affected scope (e.g. the attacker can read the administrator's password, or private keys in memory are disclosed to the attacker)."
            },
            P: {
                l: 'Partial',
                d: "<b>Bad:</b> There is informational disclosure or a bypass of access controls. Access to some restricted information is obtained, but the attacker does not have control over what is obtained, or the scope of the loss is constrained. The information disclosure does not have a direct, serious impact on the affected scope."
            },
            N: {
                l: 'None',
                d: "<b>Good:</b> There is no impact to confidentiality within the affected scope."
            }
        },
        I: {
            C: {
                l: 'Complete',
                d: "<b>Worst:</b> There is a total compromise of system integrity. There is a complete loss of system protection, resulting in the entire system being compromised. The attacker is able to modify any files on the target system."
            },
            P: {
                l: 'Partial',
                d: "<b>Bad:</b> Modification of data is possible, but the attacker does not have control over the end result of a modification, or the scope of modification is constrained. The data modification does not have a direct, serious impact on the affected scope."
            },
            N: {
                l: 'None',
                d: "<b>Good:</b> There is no impact to integrity within the affected scope."
            }
        },
        A: {
            C: {
                l: 'Complete',
                d: "<b>Worst:</b> There is total loss of availability, resulting in the attacker being able to fully deny access to resources in the affected scope; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious impact to the affected scope (e.g. the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable)."
            },
            P: {
                l: 'Partial',
                d: "<b>Bad:</b> There is reduced performance or interruptions in resource availability. The attacker does not have the ability to completely deny service to legitimate users, even through repeated exploitation of the vulnerability. The resources in the affected scope are either partially available all of the time, or fully available only some of the time, but the overall there is no direct, serious impact to the affected scope."
            },
            N: {
                l: 'None',
                d: "<b>Good:</b> There is no impact to availability within the affected scope."
            }
        }
    };

    this.bme = {};
    this.bmgReg = {
        AV: 'LAN',
        AC: 'LMH',
        AU: 'MSN',
        C: 'NPC',
        I: 'NPC',
        A: 'NPC'
    };
    this.bmoReg = {
        AV: 'NAL',
        AC: 'LMH',
        C: 'C',
        I: 'C',
        A: 'C'
    };
    var s, f, dl, g, dd, l;
    this.el = document.getElementById(id);
    this.el.appendChild(s = e('style'));
    s.innerHTML = '';
    this.el.appendChild(f = e('form'));
    f.className = 'cvssjs';
    this.calc = f;
    for (g in this.bg) {
        f.appendChild(dl = e('dl'));
        dl.setAttribute('class', g);
        var dt = e('dt');
        //dt.innerHTML = this.bg[g];
        dl.appendChild(dt);
        for (s in this.bm[g]) {
            dd = e('dd');
            dl.appendChild(dd);
            var inp = e('input');
            inp.setAttribute('name', g);
            inp.setAttribute('value', s);
            inp.setAttribute('id', id + g + s);
            inp.setAttribute('class', g + s);
            inp.setAttribute('type', 'radio');
            this.bme[g + s] = inp;
            var me = this;
            inp.onchange = function () {
                me.setMetric(this);
            };
            dd.appendChild(inp);
            l = e('label');
            dd.appendChild(l);
            l.setAttribute('for', id + g + s);
            l.appendChild(e('i')).setAttribute('class', g + s);
            l.appendChild(document.createTextNode(this.bm[g][s].l + ' '));
            //dd.appendChild(e('small')).innerHTML = this.bm[g][s].d;
        }
    }
    f.appendChild(e('hr'));
    f.appendChild(dl = e('dl'));
    dd = e('dd');
    dl.appendChild(dd);
    l = dd.appendChild(e('label'));
    l.className = 'results';
    l.appendChild(this.severity = e('span'));
    this.severity.className = 'severity';
    l.appendChild(this.score = e('span'));
    this.score.className = 'score';
    l.appendChild(document.createTextNode(' '));
    l.appendChild(this.vector = e('a'));
    this.vector.className = 'vector';
    this.vector.innerHTML = 'CVSS:2.0/AV:_/AC:_/AU:_/C:_/I:_/A:_';

};

CVSS.js.prototype.severityRatings = [{
    name: "None",
    bottom: 0.0,
    top: 0.0
}, {
    name: "Low",
    bottom: 0.1,
    top: 3.9
}, {
    name: "Medium",
    bottom: 4.0,
    top: 6.9
}, {
    name: "High",
    bottom: 7.0,
    top: 8.9
}, {
    name: "Critical",
    bottom: 9.0,
    top: 10.0
}];

CVSS.js.prototype.severityRating = function (score) {
    var i;
    var severityRatingLength = this.severityRatings.length;
    for (i = 0; i < severityRatingLength; i++) {
        if (score >= this.severityRatings[i].bottom && score <= this.severityRatings[i].top) {
            return this.severityRatings[i];
        }
    }
    return {
        name: "Disabled",
        bottom: 'Not',
        top: 'defined'
    };
};

CVSS.js.prototype.calculate = function () {
    // calculate is disabled is CVSSv2
    return '';
};

CVSS.js.prototype.get = function() {
    return {
        score: this.score.innerHTML,
        vector: this.vector.innerHTML
    }
};

CVSS.js.prototype.setMetric = function(a) {
    var vectorString = this.vector.innerHTML;
    if (/AV:.\/AC:.\/AU:.\/C:.\/I:.\/A:./.test(vectorString)) {} else {
        vectorString = 'AV:_/AC:_/AU:_/C:_/I:_/A:_';
    }
    //e("E" + a.id).checked = true;
    var newVec = vectorString.replace(new RegExp('\\b' + a.name + ':.'), a.name + ':' + a.value);
    this.set(newVec);
};

CVSS.js.prototype.set = function(vec) {
    var newVec = 'CVSS:2.0/';
    sep = '';
    for (m in this.bm) {
        if ((match = (new RegExp('\\b(' + m + ':[' + this.bmgReg[m] + '])')).exec(vec)) != null) {
            check = match[0].replace(':', '')
            this.bme[check].checked = true;
            newVec = newVec + sep + match[0];
        } else if ((m in {C:'', I:'', A:''}) && (match = (new RegExp('\\b(' + m + ':C)')).exec(vec)) != null) {
            // compatibility with v2 only for CIA:C
            this.bme[m + 'H'].checked = true;
            newVec = newVec + sep + m + ':H';
        } else {
            newVec = newVec + sep + m + ':_';
            for (var j in this.bm[m]) {
                this.bme[m + j].checked = false;
            }
        }
        sep = '/';
    }
    this.update(newVec);
};

CVSS.js.prototype.update = function(newVec) {
    this.vector.innerHTML = newVec;
    var s = this.calculate();
    //this.score.innerHTML = "CALC";
    //var rating = this.severityRating(s);
    //this.severity.className = rating.name + ' severity';
    //this.severity.innerHTML = rating.name + '<sub>' + rating.bottom + ' - ' + rating.top + '</sub>';
    //this.severity.title = rating.bottom + ' - ' + rating.top;
    if (this.options != undefined && this.options.onchange != undefined) {
        this.options.onchange();
    }
};
