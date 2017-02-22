package it.ibm.fe.sample.servlets;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/frontendService")
public class WebMessageServlet extends GenericServlet
{

	private static final long serialVersionUID = 1L;

	@Override
	protected void doService(HttpServletRequest request, HttpServletResponse response, ServiceResults serviceResults) throws ServletException,
			IOException
	{
		serviceResults.content = "fragments/service.jsp";
		appendMessage(serviceResults, "Response from " + getClass().getSimpleName() + ".doService at " + System.currentTimeMillis());
	}
}
