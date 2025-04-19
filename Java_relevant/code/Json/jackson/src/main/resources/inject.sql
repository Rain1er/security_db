CREATE ALIAS SHELLEXEC AS $$ void shellexec(String cmd) throws java.io.IOException {
String[] command = {cmd};
Runtime.getRuntime().exec(command);
}
$$;
CALL SHELLEXEC('open -a Calculator.app')