Output demo/out/mcp-agent-01-throw.gif

Require bash
Require tmux

Set Shell bash
Set FontSize 11
Set Width 1280
Set Height 720
Set TypingSpeed 10 ms
Set Padding 12
Set Framerate 20

Hide
Type "source scripts/demo-step-setup.sh && hovel_demo_setup mcp-agent-01-throw configured mcp-agent-demo"
Enter
Wait+Screen@30s /HOVEL_DEMO_READY/
Type "clear"
Enter
Show

Type "scripts/demo-mcp-agent-tmux.sh"
Enter
Wait+Screen@45s /HOVEL\/\/THROW/
Sleep 1000 ms

Hide
Type "hovel_demo_teardown"
Enter
