Output demo/out/mcp-agent-02-squatter-wine.gif

Require bash
Require docker
Require tmux

Set Shell bash
Set FontSize 11
Set Width 1280
Set Height 720
Set TypingSpeed 10 ms
Set Padding 12
Set Framerate 20

Hide
Type "source scripts/demo-step-setup.sh && hovel_demo_setup mcp-agent-02-squatter-wine squatter-wine squatter-wine-demo"
Enter
Wait+Screen@180s /HOVEL_DEMO_READY/
Type "clear"
Enter
Show

Type "HOVEL_DEMO_AGENT_SCENARIO=squatter HOVEL_DEMO_AGENT_DELAY=520ms HOVEL_DEMO_AGENT_TOKEN_DELAY=28ms scripts/demo-mcp-agent-tmux.sh"
Enter
Wait+Screen@90s /Squatter responded/
Sleep 2500 ms

Hide
Type "hovel_demo_teardown"
Enter
