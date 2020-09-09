#ifndef SDK_INCLUDE_TEE_COMMON_PROTOBUF_H_
#define SDK_INCLUDE_TEE_COMMON_PROTOBUF_H_

#define PB_PARSE(pbmsg, pbstr)                                  \
  do {                                                          \
    if (!(pbmsg).ParseFromString(pbstr)) {                      \
      ELOG_ERROR("Fail to parse protobuf message: %s", #pbmsg); \
      return TEE_ERROR_PROTOBUF_PARSE;                          \
    }                                                           \
  } while (0)

#define PB_SERIALIZE(pbmsg, p_pbstr)                                \
  do {                                                              \
    if (!(pbmsg).SerializeToString(p_pbstr)) {                      \
      ELOG_ERROR("Fail to serialize protobuf message: %s", #pbmsg); \
      return TEE_ERROR_PROTOBUF_SERIALIZE;                          \
    }                                                               \
  } while (0)

#endif  // SDK_INCLUDE_TEE_COMMON_PROTOBUF_H_
