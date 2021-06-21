from typing import Optional

from django.http import HttpRequest, JsonResponse, HttpResponse
from starlette import status
from strawberry.django.views import GraphQLView, AsyncGraphQLView, BaseView
from strawberry.http import GraphQLHTTPResponse, process_result
from strawberry.types import ExecutionResult

from strawberry_django_jwt.exceptions import JSONWebTokenError


class StatusGraphQLHTTPResponse(GraphQLHTTPResponse):
    status: Optional[int]


def make_status_response(response: GraphQLHTTPResponse) -> StatusGraphQLHTTPResponse:
    return StatusGraphQLHTTPResponse(**response, status=200)


class BaseStatusHandlingGraphQLView(BaseView):
    def process_result(
            self, request: HttpRequest, result: ExecutionResult
    ) -> StatusGraphQLHTTPResponse:
        res = make_status_response(process_result(result))
        if result.errors:
            if any(isinstance(err, JSONWebTokenError) for err in [e.original_error for e in result.errors]):
                res["status"] = status.HTTP_401_UNAUTHORIZED
        return res

    def _create_response(
            self, response_data: StatusGraphQLHTTPResponse, sub_response: HttpResponse
    ) -> JsonResponse:
        response = JsonResponse(response_data, status=response_data.get("status", None))

        for name, value in sub_response.items():
            response[name] = value

        if sub_response.status_code is not None:
            response.status_code = sub_response.status_code

        for name, value in sub_response.cookies.items():
            response.cookies[name] = value

        return response


class StatusHandlingGraphQLView(BaseStatusHandlingGraphQLView, GraphQLView):
    pass


class AsyncStatusHandlingGraphQLView(BaseStatusHandlingGraphQLView, AsyncGraphQLView):
    pass
