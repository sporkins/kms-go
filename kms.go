package sporkins

import (
	"context"
	"encoding/base64"
	"os"

	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"

	cloudkms "cloud.google.com/go/kms/apiv1"
)

var rawStdEncoding = base64.StdEncoding.WithPadding(base64.NoPadding)

//KMSClient wrappter around *cloudkms.KeyManagementClient and ctx
type KMSClient struct {
	ctx        context.Context
	client     *cloudkms.KeyManagementClient
	resourceID string
}

//NewKMSClient builds new KMSClient
func NewKMSClient(resourceID string) KMSClient {
	ctx := context.Background()
	client, err := cloudkms.NewKeyManagementClient(ctx)
	if err != nil {
		println(err.Error())
		os.Exit(-1)
	}
	return KMSClient{
		ctx:        ctx,
		client:     client,
		resourceID: resourceID,
	}
}

//Encrypt encrypt plaintext
func (k KMSClient) Encrypt(plaintext []byte) []byte {
	req := &kmspb.EncryptRequest{
		Name:      k.resourceID,
		Plaintext: plaintext,
	}

	response, err := k.client.Encrypt(k.ctx, req)
	if err != nil {
		println(err.Error())
		os.Exit(-1)
	}

	return response.Ciphertext
}
