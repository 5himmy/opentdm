/**
 * HTTP stuff
 */

void HTTP_Init (void);
void HTTP_Shutdown (void);
qboolean HTTP_QueueDownload (tdm_download_t *d);
void HTTP_ResolveOTDMServer (void);
void HTTP_PostMatchEvent(const char *event_type, const char *team_a, const char *team_b,
                         int score_a, int score_b, qboolean forfeit);
