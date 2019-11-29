package azure

type ChallengeEntity struct {
	PartitionKey, RowKey, ETag string
	Data                       string
}
