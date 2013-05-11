#ifndef __MEGA_FILE_UPLOADER_H__
#define __MEGA_FILE_UPLOADER_H__

#include <glib-object.h>

#define MEGA_TYPE_FILE_UPLOADER            (mega_file_uploader_get_type())
#define MEGA_FILE_UPLOADER(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), MEGA_TYPE_FILE_UPLOADER, MegaFileUploader))
#define MEGA_FILE_UPLOADER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass),  MEGA_TYPE_FILE_UPLOADER, MegaFileUploaderClass))
#define MEGA_IS_FILE_UPLOADER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), MEGA_TYPE_FILE_UPLOADER))
#define MEGA_IS_FILE_UPLOADER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass),  MEGA_TYPE_FILE_UPLOADER))
#define MEGA_FILE_UPLOADER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj),  MEGA_TYPE_FILE_UPLOADER, MegaFileUploaderClass))

typedef struct _MegaFileUploader MegaFileUploader;
typedef struct _MegaFileUploaderClass MegaFileUploaderClass;
typedef struct _MegaFileUploaderPrivate MegaFileUploaderPrivate;

struct _MegaFileUploader
{
  GObject parent;
  MegaFileUploaderPrivate* priv;
};

struct _MegaFileUploaderClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GType                   mega_file_uploader_get_type     (void) G_GNUC_CONST;

MegaFileUploader*       mega_file_uploader_new          (void);

G_END_DECLS

#endif
