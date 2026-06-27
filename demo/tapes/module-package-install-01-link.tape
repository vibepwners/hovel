Output demo/out/module-package-install-01-link.gif

Require bash

Set Shell bash
Set FontSize 12
Set Width 960
Set Height 620
Set TypingSpeed 13 ms
Set Padding 18
Set Framerate 20

Hide
Type "source scripts/demo-step-setup.sh && hovel_demo_setup module-package-install-01-link empty && hovel_demo_create_link_package"
Enter
Wait+Screen@30s /HOVEL_DEMO_READY/
Type "clear"
Enter
Show

Type "hovel module install --link $HOVEL_DEMO_PACKAGE --workspace $HOVEL_WORKSPACE"
Enter
Wait+Screen /Installed module linked-demo@0.1.0/
Sleep 250 ms

Type "hovel module installed --workspace $HOVEL_WORKSPACE"
Enter
Wait+Screen /linked-demo@0.1.0/
Sleep 250 ms

Type "sed -n '1,12p' $HOVEL_WORKSPACE/module-lock.yaml"
Enter
Wait+Screen /kind: ModuleLock/
Sleep 250 ms

Hide
Type "hovel_demo_teardown"
Enter
