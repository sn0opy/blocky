package resolver

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const (
	dockerResolverLogger = "docker_resolver"
)

type DockerResolver struct {
	NextResolver
	SocketPath    string
	hosts         []dockerHost
	ttl           uint32
	refreshPeriod time.Duration
}

func (r *DockerResolver) handleReverseDNS(request *model.Request) *model.Response {
	question := request.Req.Question[0]
	if question.Qtype == dns.TypePTR {
		response := new(dns.Msg)
		response.SetReply(request.Req)

		for _, dockerHost := range r.hosts {
			raddr, _ := dns.ReverseAddr(dockerHost.IP.String())

			if raddr == question.Name {
				ptr := new(dns.PTR)
				ptr.Ptr = dns.Fqdn(dockerHost.ContainerName)
				ptr.Hdr = util.CreateHeader(question, r.ttl)
				response.Answer = append(response.Answer, ptr)

				for _, alias := range dockerHost.Aliases {
					ptrAlias := new(dns.PTR)
					ptrAlias.Ptr = dns.Fqdn(alias)
					ptrAlias.Hdr = util.CreateHeader(question, r.ttl)
					response.Answer = append(response.Answer, ptrAlias)
				}

				return &model.Response{Res: response, RType: model.ResponseTypeDOCKER, Reason: "DOCKER"}
			}
		}
	}

	return nil
}

func (r *DockerResolver) Resolve(request *model.Request) (*model.Response, error) {
	logger := withPrefix(request.Log, dockerResolverLogger)

	if r.SocketPath == "" {
		return r.next.Resolve(request)
	}

	reverseResp := r.handleReverseDNS(request)
	if reverseResp != nil {
		return reverseResp, nil
	}

	if len(r.hosts) != 0 {
		response := new(dns.Msg)
		response.SetReply(request.Req)

		question := request.Req.Question[0]
		domain := util.ExtractDomain(question)

		for _, host := range r.hosts {
			if host.ContainerName == domain {
				if isSupportedType(host.IP, question) {
					rr, _ := util.CreateAnswerFromQuestion(question, host.IP, r.ttl)
					response.Answer = append(response.Answer, rr)
				}
			}

			for _, alias := range host.Aliases {
				if alias == domain {
					if isSupportedType(host.IP, question) {
						rr, _ := util.CreateAnswerFromQuestion(question, host.IP, r.ttl)
						response.Answer = append(response.Answer, rr)
					}
				}
			}
		}

		if len(response.Answer) > 0 {
			logger.WithFields(logrus.Fields{
				"answer": util.AnswerToString(response.Answer),
				"domain": domain,
			}).Debugf("returning hosts file entry")

			return &model.Response{Res: response, RType: model.ResponseTypeHOSTSFILE, Reason: "HOSTS FILE"}, nil
		}
	}

	logger.WithField("resolver", Name(r.next)).Trace("go to next resolver")

	return r.next.Resolve(request)
}

func (r *DockerResolver) Configuration() (result []string) {
	if r.SocketPath != "" && len(r.hosts) != 0 {
		result = append(result, fmt.Sprintf("docker socket path: %s", r.SocketPath))
		result = append(result, fmt.Sprintf("docker TTL: %d", r.ttl))
		result = append(result, fmt.Sprintf("docker refresh period: %s", r.refreshPeriod.String()))
	} else {
		result = []string{"deactivated"}
	}

	return
}

func NewDockerResolver(cfg config.DockerConfig) ChainedResolver {
	r := DockerResolver{
		SocketPath:    cfg.SocketPath,
		ttl:           uint32(time.Duration(cfg.HostsTTL).Seconds()),
		refreshPeriod: time.Duration(cfg.RefreshPeriod),
	}

	err := r.parseDockerContainers()

	if err != nil {
		logger := logger(dockerResolverLogger)
		logger.Warnf("cannot parse docker socket path: %s, docker resolving is disabled", r.SocketPath)
		r.SocketPath = ""
	} else {
		go r.periodicUpdate()
	}

	return &r
}

type dockerHost struct {
	IP            net.IP
	ContainerName string
	Aliases       []string
}

func (r *DockerResolver) parseDockerContainers() error {
	logger := logger(dockerResolverLogger)

	if r.SocketPath == "" {
		return nil
	}

	ctx := context.Background()

	cli, err := client.NewClientWithOpts(client.WithHost("unix://"+r.SocketPath), client.WithAPIVersionNegotiation())
	if err != nil {
		logger.Error("unable to connect to docker socket: ", err)
		return nil
	}

	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		logger.Error("unable to retrieve docker containers: ", err)
		return nil
	}

	newHosts := make([]dockerHost, 0)

	for _, container := range containers {
		containerNames := container.Names
		bridgeNetwork, exists := container.NetworkSettings.Networks["bridge"]

		// Check if container uses a bridged network
		if !exists {
			continue
		}

		var h dockerHost
		h.IP = net.ParseIP(bridgeNetwork.IPAddress)
		h.ContainerName = containerNames[0][1:]

		if len(containerNames) > 2 {
			for i := 2; i < len(containerNames); i++ {
				h.Aliases = append(h.Aliases, containerNames[i])
			}
		}

		newHosts = append(newHosts, h)
	}

	r.hosts = newHosts
	return nil
}

func (r *DockerResolver) periodicUpdate() {
	if r.refreshPeriod > 0 {
		ticker := time.NewTicker(r.refreshPeriod)
		defer ticker.Stop()

		for {
			<-ticker.C

			logger := logger(dockerResolverLogger)
			logger.WithField("socket", r.SocketPath).Debug("refreshing docker")

			err := r.parseDockerContainers()
			if err != nil {
				logger.Warn("can't refresh docker: ", err)
			}
		}
	}
}
