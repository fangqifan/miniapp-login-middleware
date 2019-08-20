!function(t,e){"object"==typeof exports&&"undefined"!=typeof module?module.exports=e(require("miniapp-token-based-login"),require("request-middleware-pipeline")):"function"==typeof define&&define.amd?define(["miniapp-token-based-login","request-middleware-pipeline"],e):t["miniapp-login-middleware"]=e(t["miniapp-token-based-login"],t["request-middleware-pipeline"])}(this,function(t,e){"use strict";function r(t,e){return e={exports:{}},t(e,e.exports),e.exports}function n(t){if("function"==typeof t)return t;var e=Array.isArray(t)?[]:{};for(var r in t){var i=t[r],a={}.toString.call(i).slice(8,-1);e[r]="Array"==a||"Object"==a?n(i):"Date"==a?new Date(i.getTime()):"RegExp"==a?RegExp(i.source,o(i)):i}return e}function o(t){if("string"==typeof t.source.flags)return t.source.flags;var e=[];return t.global&&e.push("g"),t.ignoreCase&&e.push("i"),t.multiline&&e.push("m"),t.sticky&&e.push("y"),t.unicode&&e.push("u"),e.join("")}function i(){var t=[].slice.call(arguments),e=!1;"boolean"==typeof t[0]&&(e=t.shift());var r=t[0];if(!r||"object"!=typeof r&&"function"!=typeof r)throw new Error("extendee must be an object");for(var n=t.slice(1),o=n.length,u=0;u<o;u++){var c=n[u];for(var s in c)if(c.hasOwnProperty(s)){var f=c[s];if(e&&a(f)){var l=Array.isArray(f)?[]:{};r[s]=i(!0,r[s]||l,f)}else r[s]=f}}return r}function a(t){return Array.isArray(t)||"[object Object]"=={}.toString.call(t)}function u(t,e){Object.keys(t).forEach(function(e){delete t[e]}),d(!0,t,e)}var c=("undefined"!=typeof window?window:"undefined"!=typeof global?global:"undefined"!=typeof self&&self,r(function(t){!function(e){function r(t,e,r,n){var i=e&&e.prototype instanceof o?e:o,a=Object.create(i.prototype),u=new p(n||[]);return a._invoke=s(t,r,u),a}function n(t,e,r){try{return{type:"normal",arg:t.call(e,r)}}catch(t){return{type:"throw",arg:t}}}function o(){}function i(){}function a(){}function u(t){["next","throw","return"].forEach(function(e){t[e]=function(t){return this._invoke(e,t)}})}function c(t){function e(r,o,i,a){var u=n(t[r],t,o);if("throw"!==u.type){var c=u.arg,s=c.value;return s&&"object"==typeof s&&m.call(s,"__await")?Promise.resolve(s.__await).then(function(t){e("next",t,i,a)},function(t){e("throw",t,i,a)}):Promise.resolve(s).then(function(t){c.value=t,i(c)},a)}a(u.arg)}function r(t,r){function n(){return new Promise(function(n,o){e(t,r,n,o)})}return o=o?o.then(n,n):n()}var o;this._invoke=r}function s(t,e,r){var o=O;return function(i,a){if(o===k)throw new Error("Generator is already running");if(o===_){if("throw"===i)throw a;return d()}for(r.method=i,r.arg=a;;){var u=r.delegate;if(u){var c=f(u,r);if(c){if(c===R)continue;return c}}if("next"===r.method)r.sent=r._sent=r.arg;else if("throw"===r.method){if(o===O)throw o=_,r.arg;r.dispatchException(r.arg)}else"return"===r.method&&r.abrupt("return",r.arg);o=k;var s=n(t,e,r);if("normal"===s.type){if(o=r.done?_:j,s.arg===R)continue;return{value:s.arg,done:r.done}}"throw"===s.type&&(o=_,r.method="throw",r.arg=s.arg)}}}function f(t,e){var r=t.iterator[e.method];if(r===g){if(e.delegate=null,"throw"===e.method){if(t.iterator.return&&(e.method="return",e.arg=g,f(t,e),"throw"===e.method))return R;e.method="throw",e.arg=new TypeError("The iterator does not provide a 'throw' method")}return R}var o=n(r,t.iterator,e.arg);if("throw"===o.type)return e.method="throw",e.arg=o.arg,e.delegate=null,R;var i=o.arg;return i?i.done?(e[t.resultName]=i.value,e.next=t.nextLoc,"return"!==e.method&&(e.method="next",e.arg=g),e.delegate=null,R):i:(e.method="throw",e.arg=new TypeError("iterator result is not an object"),e.delegate=null,R)}function l(t){var e={tryLoc:t[0]};1 in t&&(e.catchLoc=t[1]),2 in t&&(e.finallyLoc=t[2],e.afterLoc=t[3]),this.tryEntries.push(e)}function h(t){var e=t.completion||{};e.type="normal",delete e.arg,t.completion=e}function p(t){this.tryEntries=[{tryLoc:"root"}],t.forEach(l,this),this.reset(!0)}function y(t){if(t){var e=t[x];if(e)return e.call(t);if("function"==typeof t.next)return t;if(!isNaN(t.length)){var r=-1,n=function e(){for(;++r<t.length;)if(m.call(t,r))return e.value=t[r],e.done=!1,e;return e.value=g,e.done=!0,e};return n.next=n}}return{next:d}}function d(){return{value:g,done:!0}}var g,v=Object.prototype,m=v.hasOwnProperty,w="function"==typeof Symbol?Symbol:{},x=w.iterator||"@@iterator",b=w.asyncIterator||"@@asyncIterator",L=w.toStringTag||"@@toStringTag",E=e.regeneratorRuntime;if(E)return void(t.exports=E);E=e.regeneratorRuntime=t.exports,E.wrap=r;var O="suspendedStart",j="suspendedYield",k="executing",_="completed",R={},S={};S[x]=function(){return this};var P=Object.getPrototypeOf,q=P&&P(P(y([])));q&&q!==v&&m.call(q,x)&&(S=q);var A=a.prototype=o.prototype=Object.create(S);i.prototype=A.constructor=a,a.constructor=i,a[L]=i.displayName="GeneratorFunction",E.isGeneratorFunction=function(t){var e="function"==typeof t&&t.constructor;return!!e&&(e===i||"GeneratorFunction"===(e.displayName||e.name))},E.mark=function(t){return Object.setPrototypeOf?Object.setPrototypeOf(t,a):(t.__proto__=a,L in t||(t[L]="GeneratorFunction")),t.prototype=Object.create(A),t},E.awrap=function(t){return{__await:t}},u(c.prototype),c.prototype[b]=function(){return this},E.AsyncIterator=c,E.async=function(t,e,n,o){var i=new c(r(t,e,n,o));return E.isGeneratorFunction(e)?i:i.next().then(function(t){return t.done?t.value:i.next()})},u(A),A[L]="Generator",A[x]=function(){return this},A.toString=function(){return"[object Generator]"},E.keys=function(t){var e=[];for(var r in t)e.push(r);return e.reverse(),function r(){for(;e.length;){var n=e.pop();if(n in t)return r.value=n,r.done=!1,r}return r.done=!0,r}},E.values=y,p.prototype={constructor:p,reset:function(t){if(this.prev=0,this.next=0,this.sent=this._sent=g,this.done=!1,this.delegate=null,this.method="next",this.arg=g,this.tryEntries.forEach(h),!t)for(var e in this)"t"===e.charAt(0)&&m.call(this,e)&&!isNaN(+e.slice(1))&&(this[e]=g)},stop:function(){this.done=!0;var t=this.tryEntries[0],e=t.completion;if("throw"===e.type)throw e.arg;return this.rval},dispatchException:function(t){function e(e,n){return i.type="throw",i.arg=t,r.next=e,n&&(r.method="next",r.arg=g),!!n}if(this.done)throw t;for(var r=this,n=this.tryEntries.length-1;n>=0;--n){var o=this.tryEntries[n],i=o.completion;if("root"===o.tryLoc)return e("end");if(o.tryLoc<=this.prev){var a=m.call(o,"catchLoc"),u=m.call(o,"finallyLoc");if(a&&u){if(this.prev<o.catchLoc)return e(o.catchLoc,!0);if(this.prev<o.finallyLoc)return e(o.finallyLoc)}else if(a){if(this.prev<o.catchLoc)return e(o.catchLoc,!0)}else{if(!u)throw new Error("try statement without catch or finally");if(this.prev<o.finallyLoc)return e(o.finallyLoc)}}}},abrupt:function(t,e){for(var r=this.tryEntries.length-1;r>=0;--r){var n=this.tryEntries[r];if(n.tryLoc<=this.prev&&m.call(n,"finallyLoc")&&this.prev<n.finallyLoc){var o=n;break}}o&&("break"===t||"continue"===t)&&o.tryLoc<=e&&e<=o.finallyLoc&&(o=null);var i=o?o.completion:{};return i.type=t,i.arg=e,o?(this.method="next",this.next=o.finallyLoc,R):this.complete(i)},complete:function(t,e){if("throw"===t.type)throw t.arg;return"break"===t.type||"continue"===t.type?this.next=t.arg:"return"===t.type?(this.rval=this.arg=t.arg,this.method="return",this.next="end"):"normal"===t.type&&e&&(this.next=e),R},finish:function(t){for(var e=this.tryEntries.length-1;e>=0;--e){var r=this.tryEntries[e];if(r.finallyLoc===t)return this.complete(r.completion,r.afterLoc),h(r),R}},catch:function(t){for(var e=this.tryEntries.length-1;e>=0;--e){var r=this.tryEntries[e];if(r.tryLoc===t){var n=r.completion;if("throw"===n.type){var o=n.arg;h(r)}return o}}throw new Error("illegal catch attempt")},delegateYield:function(t,e,r){return this.delegate={iterator:y(t),resultName:e,nextLoc:r},"next"===this.method&&(this.arg=g),R}}}(function(){return this}()||Function("return this")())})),s=function(){return this}()||Function("return this")(),f=s.regeneratorRuntime&&Object.getOwnPropertyNames(s).indexOf("regeneratorRuntime")>=0,l=f&&s.regeneratorRuntime;s.regeneratorRuntime=void 0;var h=c;if(f)s.regeneratorRuntime=l;else try{delete s.regeneratorRuntime}catch(t){s.regeneratorRuntime=void 0}var p=h,y=n,d=i,g=r(function(t,e){!function(e,r){t.exports=function(){return{WxRequestOptions:"wx-request-options",WxResponse:"wx-response"}}()}()}),v=function(t){return function(){var e=t.apply(this,arguments);return new Promise(function(t,r){function n(o,i){try{var a=e[o](i),u=a.value}catch(t){return void r(t)}if(!a.done)return Promise.resolve(u).then(function(t){n("next",t)},function(t){n("throw",t)});t(u)}return n("next")})}},m=function(t,e){if(!(t instanceof e))throw new TypeError("Cannot call a class as a function")},w=function(){function t(t,e){for(var r=0;r<e.length;r++){var n=e[r];n.enumerable=n.enumerable||!1,n.configurable=!0,"value"in n&&(n.writable=!0),Object.defineProperty(t,n.key,n)}}return function(e,r,n){return r&&t(e.prototype,r),n&&t(e,n),e}}(),x=function(t,e){if("function"!=typeof e&&null!==e)throw new TypeError("Super expression must either be null or a function, not "+typeof e);t.prototype=Object.create(e&&e.prototype,{constructor:{value:t,enumerable:!1,writable:!0,configurable:!0}}),e&&(Object.setPrototypeOf?Object.setPrototypeOf(t,e):t.__proto__=e)},b=function(t,e){if(!t)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return!e||"object"!=typeof e&&"function"!=typeof e?t:e},L={attachRequestOptions:function(t,e){e&&(t.header=t.header||{},t.header.Authorization="Bearer "+e)},maxRetryCount:3,loginModule:new t.LoginModule},E={options:Symbol("options"),retryCount:Symbol("retryCount")};return function(e){function r(t,e){m(this,r);var n=b(this,(r.__proto__||Object.getPrototypeOf(r)).call(this,t));return n[E.options]=d({},L,e),n[E.retryCount]=0,n}return x(r,e),w(r,[{key:"invoke",value:function(){function e(t){return r.apply(this,arguments)}var r=v(p.mark(function e(r){var n,o,i,a,c;return p.wrap(function(e){for(;;)switch(e.prev=e.next){case 0:return n=y(r.data),o=r.data[g.WxRequestOptions]=r.data[g.WxRequestOptions]||{},i=this[E.options].loginModule.loginToken,this[E.options].attachRequestOptions(o,i),e.next=6,this.next(r);case 6:if(a=r.data[g.WxResponse]=r.data[g.WxResponse]||{},401!==a.statusCode){e.next=22;break}if(c=this[E.options].loginModule.status,c.status!==t.LoginStatusEnum.LoggedInFailed){e.next=11;break}return e.abrupt("return");case 11:return c.status===t.LoginStatusEnum.LoggedIn&&c.changeStatus(t.LoginStatusEnum.NotLoggedIn),e.next=14,this[E.options].loginModule.login();case 14:if(c.status!==t.LoginStatusEnum.LoggedIn){e.next=22;break}if(!(this[E.retryCount]>this[E.options].maxRetryCount)){e.next=18;break}return c.changeStatus(t.LoginStatusEnum.LoggedInFailed),e.abrupt("return");case 18:return this[E.retryCount]++,u(r.data,n),e.next=22,this.invoke(r);case 22:case"end":return e.stop()}},e,this)}));return e}()},{key:"config",value:function(t){this[E.options]=d(this[E.options],t)}}]),r}(e.Middleware)});
//# sourceMappingURL=index.js.map
