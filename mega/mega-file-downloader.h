#ifndef __MEGA_FILE_DOWNLOADER_H__
#define __MEGA_FILE_DOWNLOADER_H__

#include <glib-object.h>

#define MEGA_TYPE_FILE_DOWNLOADER            (mega_file_downloader_get_type())
#define MEGA_FILE_DOWNLOADER(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), MEGA_TYPE_FILE_DOWNLOADER, MegaFileDownloader))
#define MEGA_FILE_DOWNLOADER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass),  MEGA_TYPE_FILE_DOWNLOADER, MegaFileDownloaderClass))
#define MEGA_IS_FILE_DOWNLOADER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), MEGA_TYPE_FILE_DOWNLOADER))
#define MEGA_IS_FILE_DOWNLOADER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass),  MEGA_TYPE_FILE_DOWNLOADER))
#define MEGA_FILE_DOWNLOADER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj),  MEGA_TYPE_FILE_DOWNLOADER, MegaFileDownloaderClass))

typedef struct _MegaFileDownloader MegaFileDownloader;
typedef struct _MegaFileDownloaderClass MegaFileDownloaderClass;
typedef struct _MegaFileDownloaderPrivate MegaFileDownloaderPrivate;

struct _MegaFileDownloader
{
  GObject parent;
  MegaFileDownloaderPrivate* priv;
};

struct _MegaFileDownloaderClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GType                   mega_file_downloader_get_type   (void) G_GNUC_CONST;

MegaFileDownloader*     mega_file_downloader_new        (void);

G_END_DECLS

#endif
