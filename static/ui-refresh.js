/* Progressive UI polish: render stored UTC timestamps as IST without changing stored data. */
(function () {
  'use strict';

  var timestampPattern = /\b(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?)(Z|[+-]\d{2}:?\d{2})?(\s*UTC)?\b/gi;
  var formatter = new Intl.DateTimeFormat('en-IN', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit', hour12: true,
    timeZone: 'Asia/Kolkata'
  });

  function formatTimestamp(match, datePart, timePart, zonePart) {
    var zone = zonePart || 'Z';
    if (/^[+-]\d{4}$/.test(zone)) zone = zone.slice(0, 3) + ':' + zone.slice(3);
    var time = timePart.length === 5 ? timePart + ':00' : timePart;
    var parsed = new Date(datePart + 'T' + time + zone);
    if (Number.isNaN(parsed.getTime())) return match;
    return formatter.format(parsed).replace(/\b(am|pm)\b/i, function (part) { return part.toUpperCase(); }) + ' IST';
  }

  function updateTextNode(node) {
    if (!node || !node.nodeValue) return;
    var value = node.nodeValue;
    var updated = value.replace(timestampPattern, formatTimestamp);
    updated = updated.replace(/\b(Timestamp|Created|Uploaded|Updated|Recorded|Submitted)\s*\(UTC\)/gi, '$1 (IST)');
    updated = updated.replace(/\bCreated\s*\(UTC\)\s*\(sort\)/gi, 'Created (IST) (sort)');
    if (updated !== value) node.nodeValue = updated;
  }

  function walkText(root) {
    if (!root) return;
    var excluded = 'SCRIPT, STYLE, TEXTAREA, INPUT, NOSCRIPT';
    if (root.nodeType === Node.TEXT_NODE) {
      if (!root.parentElement || !root.parentElement.closest(excluded)) updateTextNode(root);
      return;
    }
    if (root.nodeType !== Node.ELEMENT_NODE && root.nodeType !== Node.DOCUMENT_NODE) return;
    var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    var node;
    while ((node = walker.nextNode())) {
      if (!node.parentElement || !node.parentElement.closest(excluded)) updateTextNode(node);
    }
  }

  function start() {
    walkText(document.body);
    if (window.MutationObserver && document.body) {
      var observer = new MutationObserver(function (records) {
        records.forEach(function (record) {
          if (record.type === 'characterData') updateTextNode(record.target);
          record.addedNodes && record.addedNodes.forEach(walkText);
        });
      });
      observer.observe(document.body, { subtree: true, childList: true, characterData: true });
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true });
  else start();
})();
