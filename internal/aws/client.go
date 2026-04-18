package aws

import (
	"context"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/applicationautoscaling"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/signer"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type AWSClient struct {
	Config  aws.Config
	Region  string
	Account string

	mu             sync.Mutex
	ecsClient      *ecs.Client
	eksClient      *eks.Client
	lambdaClient   *lambda.Client
	ecrClient      *ecr.Client
	cwClient       *cloudwatch.Client
	logsClient     *cloudwatchlogs.Client
	iamClient      *iam.Client
	signerClient   *signer.Client
	stsClient      *sts.Client
	aasClient      *applicationautoscaling.Client
}

func NewClient(ctx context.Context, region, profile string) (*AWSClient, error) {
	opts := []func(*config.LoadOptions) error{
		config.WithRegion(region),
	}
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}

	client := &AWSClient{Config: cfg, Region: region}

	stsC := sts.NewFromConfig(cfg)
	id, err := stsC.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err == nil && id.Account != nil {
		client.Account = *id.Account
	}

	return client, nil
}

func (c *AWSClient) ECS() *ecs.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ecsClient == nil {
		c.ecsClient = ecs.NewFromConfig(c.Config)
	}
	return c.ecsClient
}

func (c *AWSClient) EKS() *eks.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.eksClient == nil {
		c.eksClient = eks.NewFromConfig(c.Config)
	}
	return c.eksClient
}

func (c *AWSClient) Lambda() *lambda.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lambdaClient == nil {
		c.lambdaClient = lambda.NewFromConfig(c.Config)
	}
	return c.lambdaClient
}

func (c *AWSClient) ECR() *ecr.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ecrClient == nil {
		c.ecrClient = ecr.NewFromConfig(c.Config)
	}
	return c.ecrClient
}

func (c *AWSClient) CloudWatch() *cloudwatch.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cwClient == nil {
		c.cwClient = cloudwatch.NewFromConfig(c.Config)
	}
	return c.cwClient
}

func (c *AWSClient) CloudWatchLogs() *cloudwatchlogs.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.logsClient == nil {
		c.logsClient = cloudwatchlogs.NewFromConfig(c.Config)
	}
	return c.logsClient
}

func (c *AWSClient) IAM() *iam.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.iamClient == nil {
		c.iamClient = iam.NewFromConfig(c.Config)
	}
	return c.iamClient
}

func (c *AWSClient) Signer() *signer.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.signerClient == nil {
		c.signerClient = signer.NewFromConfig(c.Config)
	}
	return c.signerClient
}

func (c *AWSClient) AppAutoScaling() *applicationautoscaling.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.aasClient == nil {
		c.aasClient = applicationautoscaling.NewFromConfig(c.Config)
	}
	return c.aasClient
}
