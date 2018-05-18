(function(mod) {
    if (typeof exports == "object" && typeof module == "object") // CommonJS
      mod(require("../../lib/codemirror"));
    else if (typeof define == "function" && define.amd) // AMD
      define(["../../lib/codemirror"], mod);
    else // Plain browser env
      mod(CodeMirror);
  })(function(CodeMirror) {
  "use strict";

    function function_regex (functions){
        console.log("^((" + functions.join("(?=\\())|(") + "(?=\\()))")
        return new RegExp("^((" + functions.join("(?=\\())|(") + "(?=\\()))");
    }

    var function_list = function_regex(["translate", "not", "contains", "text"])

    CodeMirror.defineMode("serpico", function(){
        return {
        token: function(stream) {
            if(stream.match(/^.*←$/)){
                return "error";
            }
            if(stream.match(function_list)){
                return "keyword";
            }
            var ch = stream.next().toString();
            if(ch === "†" || ch === "¥"){
                return "condition";
            }
            if(ch === "¬" || ch === "∆"){
                return "loop";
            }
            if(ch === "µ" || ch === "ƒ" || ch === "÷" || ch === "å" || ch === "≠"){
                return "choose";
            }
            if(ch === "æ" || ch === "∞"){
                return "row-loop";
            }
            if(ch === "\"" || ch === "'"){
                var regex = new RegExp("[^"+ch+"]")
                while (!stream.eol()) {
                    //stream.eatWhile(/[^'"]/);
                    stream.eatWhile(regex);
                    console.log(stream.current())
                    //stream.eat(/['"]/);
                    if(stream.eat(ch)){
                        return "string";
                    }
                    else{
                        return "string error"
                    }
                }
            }
            
        },
        fold: "indent"
        }
    });

    CodeMirror.defineMIME("text/x-serpico","serpico")
});