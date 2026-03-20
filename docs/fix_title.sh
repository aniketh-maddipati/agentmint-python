#!/bin/bash
# Fix docs/index.html title (bug 3.8)
cd "$(dirname "$0")"
if [ -f index.html ]; then
  sed -i 's/AI Agent Identity Gateway/Independent Notary for AI Agent Actions/g' index.html
  sed -i 's/<span>AI Agent Identity<\/span>/<span>Independent Notary<\/span>/g' index.html
  echo "Fixed docs/index.html title"
else
  echo "index.html not found"
fi
