# Mongoose-Single-Page-Applications
A demo of single-page applications, using Cesanta Mongoose web server and written in C.

This is unfinished and does not work.

I plan to add the page HTML, CSS and Javascript to a C file for each page, which will use a struct called "page".

This struct contains the content (HTML, CSS, JS), a function pointer to an event handler for each page, and a
boolean for whether or not the page requires authorisation.
