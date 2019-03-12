$(document).ready(function() {
	setConvertToListListener();
});

/* Escape user input before inserting it into regexp */
function escapeRegExp(str) {
	return str.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
}

/* add event listener for each texterea with allowMarkupShortcut class */
function setConvertToListListener(){
	var elements = $("textarea.allowMarkupShortcut");
	for(var i=0; i<elements.length;i++)
		elements[i].addEventListener("keydown",ConvertToList);
}

function removeAllTags(line, tags){
	var matched;

	for(tag in tags){
		tags[tag].regex = new RegExp("^"+escapeRegExp(tags[tag].startTag)+".*"+escapeRegExp(tags[tag].endTag)+"$");
	}

	do {
		matched = false;
		for(tag in tags){
			if(line.match(tags[tag].regex)){
				matched = true;
				line = line.substr(tags[tag].startTag.length, line.length - (tags[tag].startTag.length + tags[tag].endTag.length));
			}
		}
	} while(matched)

	return line

}

function ConvertToList(event){
	var listTagByKeyPressed = {
		"w" : {"startTag": "*-", "endTag": "-*"},
		"c" : {"startTag": "[[[", "endTag": "]]]"},
		"x" : {"startTag": "[~~", "endTag": "~~]"},
		"q" : {"startTag": "[==", "endTag": "==]"}
	}

	if(event.altKey && event.ctrlKey){
		var tags;
		/* Check if a tag is defined for the pressed key*/
		if(listTagByKeyPressed[event.key] === undefined)
			return
		else
			tags = listTagByKeyPressed[event.key]

		/* Get the limit of the selection inside of the textarea */
		var startSelection = event.target.selectionStart
		var endSelection = event.target.selectionEnd

		/* Get only complete line of selected text */
		var fullText = event.target.value

		while(fullText[startSelection-1] !== "\n" && startSelection > 0)
			startSelection--;

		while(fullText[endSelection] !== "\n" && endSelection !== fullText.length)
			endSelection++;

		var textToEdit = fullText.slice(startSelection, endSelection)
		var listRow = textToEdit.split("\n");

		/* check from first line if must must add or remove tags */
		var tagIsPresent = false;

		var regexTag = new RegExp("^"+escapeRegExp(tags.startTag)+".*"+escapeRegExp(tags.endTag)+"$");

		/* for each line, remove all tags, an if necessary, add the new tags corresponding to the pressed key */
		if(listRow[0].match(regexTag))
			tagIsPresent = true;

		for(var i=0; i<listRow.length; i++){
			listRow[i] = removeAllTags(listRow[i], listTagByKeyPressed)

			if(!tagIsPresent && listRow[i] !== "")
				listRow[i] = tags.startTag + listRow[i] + tags.endTag;
		}

		/* place the modified text in the textarea */
		event.target.value = fullText.substr(0, startSelection) + listRow.join("\n") + fullText.substr(endSelection , fullText.length - endSelection +1)
	}
}
