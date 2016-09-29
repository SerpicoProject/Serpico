/* ===================================================
* bootstrap-suggest.js v1.2.2
* http://github.com/lodev09/bootstrap-suggest
* ===================================================
* Copyright 2014 Jovanni Lo
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
* ========================================================== */

(function ($) {

	"use strict"; // jshint ;_;

	var Suggest = function(el, key, options) {
		var that = this;

		this.$element = $(el);
		this.$items = undefined;
		this.options = $.extend(true, {}, $.fn.suggest.defaults, options, this.$element.data(), this.$element.data('options'));
		this.key = key;
		this.isShown = false;
		this.query = '';
		this._queryPos = [];
		this._keyPos = -1;

		this.$dropdown = $('<div />', {
			'class': 'dropdown suggest ' + this.options.dropdownClass,
			'html': $('<ul />', {'class': 'dropdown-menu', role: 'menu'}),
			'data-key': this.key
		});

		this.load();

	};

	Suggest.prototype = {
		__setListener: function() {
			this.$element
			.on('suggest.show', $.proxy(this.options.onshow, this))
			.on('suggest.select', $.proxy(this.options.onselect, this))
			.on('suggest.lookup', $.proxy(this.options.onlookup, this))
			.on('keyup', $.proxy(this.__keyup, this));

			return this;
		},

		__getCaretPos: function(posStart) {
			// https://github.com/component/textarea-caret-position/blob/master/index.js

			// The properties that we copy into a mirrored div.
			// Note that some browsers, such as Firefox,
			// do not concatenate properties, i.e. padding-top, bottom etc. -> padding,
			// so we have to do every single property specifically.
			var properties = [
				'direction',  // RTL support
				'boxSizing',
				'width',  // on Chrome and IE, exclude the scrollbar, so the mirror div wraps exactly as the textarea does
				'height',
				'overflowX',
				'overflowY',  // copy the scrollbar for IE

				'borderTopWidth',
				'borderRightWidth',
				'borderBottomWidth',
				'borderLeftWidth',

				'paddingTop',
				'paddingRight',
				'paddingBottom',
				'paddingLeft',

				// https://developer.mozilla.org/en-US/docs/Web/CSS/font
				'fontStyle',
				'fontVariant',
				'fontWeight',
				'fontStretch',
				'fontSize',
				'fontSizeAdjust',
				'lineHeight',
				'fontFamily',

				'textAlign',
				'textTransform',
				'textIndent',
				'textDecoration',  // might not make a difference, but better be safe

				'letterSpacing',
				'wordSpacing'
			];

			var isFirefox = !(window.mozInnerScreenX == null);

			var getCaretCoordinatesFn = function (element, position, recalculate) {
				// mirrored div
				var div = document.createElement('div');
				div.id = 'input-textarea-caret-position-mirror-div';
				document.body.appendChild(div);

				var style = div.style;
				var computed = window.getComputedStyle? getComputedStyle(element) : element.currentStyle;  // currentStyle for IE < 9

				// default textarea styles
				style.whiteSpace = 'pre-wrap';
				if (element.nodeName !== 'INPUT')
				style.wordWrap = 'break-word';  // only for textarea-s

				// position off-screen
				style.position = 'absolute';  // required to return coordinates properly
				style.visibility = 'hidden';  // not 'display: none' because we want rendering

				// transfer the element's properties to the div
				$.each(properties, function (index, value)
				{
					style[value] = computed[value];
				});

				if (isFirefox) {
					style.width = parseInt(computed.width) - 2 + 'px';  // Firefox adds 2 pixels to the padding - https://bugzilla.mozilla.org/show_bug.cgi?id=753662
					// Firefox lies about the overflow property for textareas: https://bugzilla.mozilla.org/show_bug.cgi?id=984275
					if (element.scrollHeight > parseInt(computed.height))
					style.overflowY = 'scroll';
				} else {
					style.overflow = 'hidden';  // for Chrome to not render a scrollbar; IE keeps overflowY = 'scroll'
				}

				div.textContent = element.value.substring(0, position);
				// the second special handling for input type="text" vs textarea: spaces need to be replaced with non-breaking spaces - http://stackoverflow.com/a/13402035/1269037
				if (element.nodeName === 'INPUT')
				div.textContent = div.textContent.replace(/\s/g, "\u00a0");

				var span = document.createElement('span');
				// Wrapping must be replicated *exactly*, including when a long word gets
				// onto the next line, with whitespace at the end of the line before (#7).
				// The  *only* reliable way to do that is to copy the *entire* rest of the
				// textarea's content into the <span> created at the caret position.
				// for inputs, just '.' would be enough, but why bother?
				span.textContent = element.value.substring(position) || '.';  // || because a completely empty faux span doesn't render at all
				div.appendChild(span);

				var coordinates = {
					top: span.offsetTop + parseInt(computed['borderTopWidth']),
					left: span.offsetLeft + parseInt(computed['borderLeftWidth'])
				};

				document.body.removeChild(div);

				return coordinates;
			}

			return getCaretCoordinatesFn(this.$element.get(0), posStart);
		},

		__keyup: function(e) {
			// don't query special characters
			// http://mikemurko.com/general/jquery-keycode-cheatsheet/
			var specialChars = [38, 40, 37, 39, 17, 18, 9, 16, 20, 91, 93, 36, 35, 45, 33, 34, 144, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 145, 19],
			$resultItems;

			switch (e.keyCode) {
				case 27:
					this.hide();
					return;
				case 13:
					return true;
			}

			if ($.inArray(e.keyCode, specialChars) !== -1) return true;

			var $el = this.$element,
			val = $el.val(),
			currentPos = this.__getSelection($el.get(0)).start;
			for (var i = currentPos; i >= 0; i--) {
				var subChar = $.trim(val.substring(i-1, i));
				if (!subChar) {
					this.hide();
					break;
				}
				if (subChar === this.key && $.trim(val.substring(i-2, i-1)) == '') {
					this.query = val.substring(i, currentPos);
					this._queryPos = [i, currentPos];
					this._keyPos = i;
					this.lookup(this.query);
					break;
				}
			}
		},

		__getVisibleItems: function() {
			return this.$items ? this.$items.not('.hidden') : $();
		},

		__build: function() {
			var elems = [], $item,
			$dropdown = this.$dropdown,
			that = this;

			var blur = function(e) {
				that.hide();
			}

			$dropdown
			.on('click', 'li:has(a)', function(e) {
				e.preventDefault();
				that.__select($(this).index());
				that.$element.focus();
			})
			.on('mouseover', 'li:has(a)', function(e) {
				that.$element.off('blur', blur);
			})
			.on('mouseout', 'li:has(a)', function(e) {
				that.$element.on('blur', blur);
			});

			this.$element.before($dropdown)
			.on('blur', blur)
			.on('keydown', function(e) {
				var $visibleItems;
				if (that.isShown) {
					switch (e.keyCode) {
						case 13: // enter key
							$visibleItems = that.__getVisibleItems();
							$visibleItems.each(function(index) {
								if ($(this).is('.active'))
								that.__select($(this).index());
							});

							return false;
							break;
						case 40: // arrow down
							$visibleItems = that.__getVisibleItems();
							if ($visibleItems.last().is('.active')) return false;
							$visibleItems.each(function(index) {
								var $this = $(this),
								$next = $visibleItems.eq(index + 1);

								//if (!$next.length) return false;

								if ($this.is('.active')) {
									if (!$next.is('.hidden')) {
										$this.removeClass('active');
										$next.addClass('active');
									}
									return false;
								}
							});
							return false;
						case 38: // arrow up
							$visibleItems = that.__getVisibleItems();
							if ($visibleItems.first().is('.active')) return false;
							$visibleItems.each(function(index) {
								var $this = $(this),
								$prev = $visibleItems.eq(index - 1);

								//if (!$prev.length) return false;

								if ($this.is('.active')) {
									if (!$prev.is('.hidden')) {
										$this.removeClass('active');
										$prev.addClass('active');
									}
									return false;
								}
							})
							return false;
					}
				}
			});

		},

		__mapItem: function(dataItem) {
			var itemHtml, that = this,
			_item = {
				text: '',
				value: ''
			};

			if (this.options.map) {
				dataItem = this.options.map(dataItem);
				if (!dataItem) return false;
			}

			if (dataItem instanceof Object) {
				_item.text = dataItem.text || '';
				_item.value = dataItem.value || '';
			} else {
				_item.text = dataItem;
				_item.value = dataItem;
			}

			return $('<li />', {'data-value': _item.value}).html($('<a />', {
				href: '#',
				html: _item.text
			}));
		},

		__select: function(index) {
			var $el = this.$element,
			el = $el.get(0),
			val = $el.val(),
			item = this.get(index),
			setCaretPos = this._keyPos + item.value.length + 1;

			$el.val(val.slice(0, this._keyPos) + item.value + ' ' + val.slice(this.__getSelection(el).start));

			if (el.setSelectionRange) {
				el.setSelectionRange(setCaretPos, setCaretPos);
			} else if (el.createTextRange) {
				var range = el.createTextRange();
				range.collapse(true);
				range.moveEnd('character', setCaretPos);
				range.moveStart('character', setCaretPos);
				range.select();
			}

			$el.trigger($.extend({type: 'suggest.select'}, this), item);

			this.hide();
		},

		__getSelection: function (el)
		{
			var start = 0,
			end = 0,
			rawValue,
			normalizedValue,
			range,
			textInputRange,
			len,
			endRange;
			el.focus();//in IE9 selectionStart will always be 9 if not focused(when selecting using the mouse)
			if (typeof el.selectionStart == "number" && typeof el.selectionEnd == "number") {
				start = el.selectionStart;
				end = el.selectionEnd;
			} else {
				range = document.selection.createRange();

				if (range && range.parentElement() === el) {
					rawValue = el.value;
					len = rawValue.length;
					normalizedValue = rawValue.replace(/\r\n/g, "\n");

					// Create a working TextRange that lives only in the input
					textInputRange = el.createTextRange();
					textInputRange.moveToBookmark(range.getBookmark());

					// Check if the start and end of the selection are at the very end
					// of the input, since moveStart/moveEnd doesn't return what we want
					// in those cases
					endRange = el.createTextRange();
					endRange.collapse(false);

					if (textInputRange.compareEndPoints("StartToEnd", endRange) > -1) {
						start = end = len;
					} else {
						start = -textInputRange.moveStart("character", -len);
						start += normalizedValue.slice(0, start).split("\n").length - 1;

						if (textInputRange.compareEndPoints("EndToEnd", endRange) > -1) {
							end = len;
						} else {
							end = -textInputRange.moveEnd("character", -len);
							end += normalizedValue.slice(0, end).split("\n").length - 1;
						}
					}

					/// normalize newlines
					start -= (rawValue.substring(0, start).split('\r\n').length - 1);
					end -= (rawValue.substring(0, end).split('\r\n').length - 1);
					/// normalize newlines
				}
			}
			return {
				start: start,
				end: end
			};
		},

		__buildItems: function(data) {
			var $dropdownMenu = this.$dropdown.find('.dropdown-menu');
			$dropdownMenu.empty();
			if (data && data instanceof Array) {
				for (var i in data) {
					var $item = this.__mapItem(data[i]);
					if ($item) {
						$dropdownMenu.append($item);
					}
				}
			}
			return $dropdownMenu.find('li:has(a)');
		},

		__lookup: function(q, $resultItems) {
			this.$element.trigger($.extend({type: 'suggest.lookup'}, this), [q, $resultItems]);
			var active = $resultItems.eq(0).addClass('active');
			if ($resultItems && $resultItems.length) {
				this.show();
			} else {
				this.hide();
			}
		},

		__filterData: function(q, data) {
			var options = this.options;
			this.$items.addClass('hidden');
			this.$items.filter(function (index) {

				// return the limit if q is empty
				if (q === '') return index < options.filter.limit;

				var $this = $(this),
				value = $this.find('a:first').text();

				if (!options.filter.casesensitive) {
					value = value.toLowerCase();
					q = q.toLowerCase();
				}
				return value.indexOf(q) != -1;
			}).slice(0, options.filter.limit).removeClass('hidden active');
			return this.__getVisibleItems();
		},

		get: function(index) {
			if(!this.$items) { return; }
			var $item = this.$items.eq(index);
			return {
				text: $item.children('a:first').text(),
				value: $item.attr('data-value'),
				index: index,
				$element: $item
			};
		},

		lookup: function(q) {
			var options = this.options,
			that = this,
			data;

			if (typeof this.options.data == 'function') {
				this.$items = undefined;
				data = this.options.data(q);
			} else {
				data = this.options.data;
			}

			if(data && $.isFunction(data.promise)) {
				data.done(function(data) {
					if(data && data.length > options.filter.limit) {
						data = data.slice(0, options.filter.limit);
					}
					that.$items = that.__buildItems(data);
					that.__lookup(q, that.$items);
				});
			} else {
				if(!this.$items) {
					this.$items = this.__buildItems(data);
				}
				var items;
				items = this.__filterData(q, data);
				this.__lookup(q, items);
			}
		},

		load: function() {
			this.__setListener();
			this.__build();
		},

		hide: function() {
			this.$dropdown.removeClass('open');
			this.isShown = false;
			if(this.$items) {
				this.$items.removeClass('active');
			}
			this._keyPos = -1;
		},

		show: function() {
			var $el = this.$element,
			$dropdownMenu = this.$dropdown.find('.dropdown-menu'),
			el = $el.get(0),
			options = this.options,
			caretPos,
			position = {
				top: 'auto',
				bottom: 'auto',
				left: 'auto',
				right: 'auto'
			};

			if (!this.isShown) {

				this.$dropdown.addClass('open');
				if (options.position !== false) {

					caretPos = this.__getCaretPos(this._keyPos);

					if (typeof options.position == 'string') {
						switch (options.position) {
							case 'bottom':
								position.top = $el.outerHeight() - parseFloat($dropdownMenu.css('margin-top'));
								position.left = 0;
								position.right = 0;
								break;
							case 'top':
								position.top = -($dropdownMenu.outerHeight(true) + parseFloat($dropdownMenu.css('margin-top')));
								position.left = 0;
								position.right = 0;
								break;
							case 'caret':
								position.top = caretPos.top - el.scrollTop;
								position.left = caretPos.left - el.scrollLeft;
								break;
						}

					} else {
						position = $.extend(position, typeof options.position == 'function' ? options.position(el, caretPos) : options.position);
					}

					$dropdownMenu.css(position);
				}

				this.isShown = true;
				$el.trigger($.extend({type: 'suggest.show'}, this));
			}
		}
	};

	var old = $.fn.suggest;

	// .suggest( key [, options] )
	// .suggest( method [, options] )
	// .suggest( suggestions )
	$.fn.suggest = function(arg1) {
		var arg2 = arguments[1];

		var createSuggest = function(el, suggestions) {
			var newData = {};
			$.each(suggestions, function(keyChar, options) {
				var key =  keyChar.toString().charAt(0);
				newData[key] = new Suggest(el, key, typeof options == 'object' && options);
			});

			return newData;
		};

		return this.each(function() {
			var that = this,
			$this = $(this),
			data = $this.data('suggest'),
			suggestion = {};

			if (typeof arg1 == 'string') {
				if (arg1.length > 1 && data) {
					// arg1 as a method
					if (typeof data[arg1] != 'undefined') data[arg1](arg2);
				} else if (arg1.length == 1) {
					// arg1 as key
					if (arg2) {

						// inline data determined if it's an array
						suggestion[arg1] = arg2 instanceof Array ? {data: arg2} : arg2;
						if (!data) {
							$this.data('suggest', createSuggest(this, suggestion));
						} else if (data && !arg1 in data) {
							$this.data('suggest', $.extend(data, createSuggest(this, suggestion)));
						}
					}
				}
			} else {
				// arg1 contains set of suggestions
				if (!data) $this.data('suggest', createSuggest(this, arg1));
				else if (data) {
					$.each(arg1, function(key, value) {
						if (key in data == false) {
							suggestion[key] = value;
						}
					});

					$this.data('suggest', $.extend(data, createSuggest(that, suggestion)))
				}
			}
		});
	};

	$.fn.suggest.defaults = {
		data: [],
		map: undefined,
		filter: {
			casesensitive: false,
			limit: 5
		},
		dropdownClass: '',
		position: 'caret',
		// events hook
		onshow: function(e) {},
		onselect: function(e, item) {},
		onlookup: function(e, item) {}

	}

	$.fn.suggest.Constructor = Suggest;

	$.fn.suggest.noConflict = function () {
		$.fn.suggest = old;
		return this;
	}

}( jQuery ));
